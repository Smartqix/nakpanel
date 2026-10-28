(function () {
  'use strict';

  function restoreNotificationFocus(trigger, fallback) {
    const visible=node=>node?.isConnected&&!node.disabled&&node.getClientRects().length>0;
    const target=visible(trigger)?trigger:visible(fallback)?fallback:null;
    if(target){if(target.tabIndex<0)target.setAttribute('tabindex','-1');target.focus();}
  }

  function notificationTime(value, now = Date.now(), locale) {
    const date = new Date(value);
    if (!value || !Number.isFinite(date.getTime())) return {label:'Unknown time', datetime:'', title:'Unknown time'};
    const age = Math.max(0, Number(now) - date.getTime());
    const label = age < 60000 ? 'Just now' : age < 3600000 ? Math.floor(age/60000)+' min ago' : age < 86400000 ? Math.floor(age/3600000)+' hr ago' : new Intl.DateTimeFormat(locale,{day:'numeric',month:'short',year:'numeric'}).format(date);
    return {label, datetime:date.toISOString(), title:new Intl.DateTimeFormat(locale,{year:'numeric',month:'short',day:'numeric',hour:'numeric',minute:'2-digit',timeZoneName:'short'}).format(date)};
  }

  function notificationPopoverPosition(trigger, viewport) {
    const inset=12, width=Math.max(0,Math.min(400,viewport.width-24));
    const top=Math.min(Math.max(inset,trigger.bottom+8),Math.max(inset,viewport.height-12));
    return {left:Math.max(inset,Math.min(trigger.right-width,viewport.width-width-inset)),top,width,maxHeight:Math.max(0,Math.min(viewport.width<=760?620:560,viewport.height-top-inset))};
  }

  function notificationBadge(count) {
    count=Math.max(0,Number(count)||0);
    return {text:count>99?'99+':count?String(count):'',label:'Notifications'+(count?', '+count+' unread':''),hidden:count===0};
  }

  function notificationPreviewQuery(scope, status) {
    const source=new URLSearchParams(scope), q=new URLSearchParams();
    for (const key of ['resource_kind','resource_id']) if(source.has(key))q.set(key,source.get(key));
    q.set('view','inbox');q.set('limit','5');if(status==='unread')q.set('status','unread');
    return q;
  }

  function createNotificationActions(env) {
    const active=new Map();let destroyed=false;
    function run(id,action,options={}) {
      const identity=env.identity(),key=identity+'|'+id;
      if(destroyed||options.isCurrent&&!options.isCurrent())return Promise.resolve(false);
      if(active.has(key))return active.get(key).promise;
      let finish;const promise=new Promise(resolve=>finish=resolve),controller=new AbortController();
      const current=()=>!destroyed&&identity===env.identity()&&!controller.signal.aborted&&(!options.isCurrent||options.isCurrent());
      const abort=()=>controller.abort();if(options.signal){if(options.signal.aborted)abort();else options.signal.addEventListener('abort',abort,{once:true});}
      active.set(key,{promise,controller});env.pending(id,true);
      (async()=>{let saved=false,result=false;try{await env.mutate(id,action,controller.signal);saved=true;if(current()){env.clearError?.();await env.success(id,action);await env.refresh();result=true;}}catch(error){if(current()){if(saved)env.error(Error('Notification status was saved, but the view could not refresh. Check again.'),()=>env.refresh());else env.error(error,()=>run(id,action,options));}}finally{active.delete(key);options.signal?.removeEventListener('abort',abort);if(identity===env.identity()&&!destroyed)env.pending(id,false);finish(result);}})();
      return promise;
    }
    return {run,destroy(){destroyed=true;active.forEach(entry=>entry.controller.abort());active.clear();}};
  }

  async function loadNotificationDetail(env) {
    try {const data=await env.load();if(!env.isCurrent())return false;env.render(data);if(!env.isCurrent())return false;await env.read(data);return env.isCurrent();}
    catch(error){if(env.isCurrent()&&error.name!=='AbortError')env.error(error);return false;}
  }

  function dateGroup(value, now, locale) {
    const date=new Date(value), today=new Date(now);
    if(!Number.isFinite(date.getTime()))return {key:'unknown',label:'Unknown date'};
    const key=d=>d.getFullYear()+'-'+(d.getMonth()+1)+'-'+d.getDate(), yesterday=new Date(today);
    yesterday.setDate(today.getDate()-1);
    return {key:key(date),label:key(date)===key(today)?'Today':key(date)===key(yesterday)?'Yesterday':new Intl.DateTimeFormat(locale,{day:'numeric',month:'short',year:'numeric'}).format(date)};
  }

  function createNotificationView(root, options) {
    const doc=root.ownerDocument, rows=new Map(), pending=new Set(), dates=new Map();
    let destroyed=false, deferred, menuID=null, latest=[], context={identity:options.identity};
    const make=(tag,text,cls)=>{const n=doc.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;};
    const icon=name=>{const svg=doc.createElementNS('http://www.w3.org/2000/svg','svg'),use=doc.createElementNS('http://www.w3.org/2000/svg','use');for(const [key,value]of Object.entries({class:'np-icon',viewBox:'0 0 24 24',fill:'none',stroke:'currentColor','stroke-width':'1.5','stroke-linecap':'round','stroke-linejoin':'round','aria-hidden':'true'}))svg.setAttribute(key,value);use.setAttribute('href','/assets/icons.svg#'+name);svg.append(use);return svg;};
    const action=(text,name)=>{const b=make('button');b.type='button';b.append(icon(name),make('span',text));return b;};
    const busy=id=>pending.has('all')||pending.has(String(id));
    const container=root.closest?.('.np-notification-preview, .np-notification-inbox');
    const errorRoot=options.errorRoot||container?.querySelector('[data-np-notification-error]');

    function construct(item) {
      const row=make('article',undefined,'np-notification-row');row.dataset.npNotificationId=String(item.id);
      const badge=make('span',undefined,'np-notification-icon'),message=make('button',undefined,'np-notification-message');message.type='button';message.dataset.npNotificationOpen=String(item.id);
      const title=make('span','', 'np-notification-title'),summary=make('span','', 'np-notification-summary'),meta=make('span',undefined,'np-notification-meta'),target=make('span','', 'np-notification-target'),time=make('time');
      meta.append(target,make('span','·'),time);message.append(title,summary,meta);
      const end=make('div',undefined,'np-notification-row-actions'),dot=make('span',undefined,'np-notification-dot'),more=action('', 'ellipsis'),menu=make('div',undefined,'np-notification-menu');dot.setAttribute('aria-hidden','true');more.className='np-notification-icon-button';more.dataset.npNotificationMenu=String(item.id);more.setAttribute('aria-expanded','false');menu.hidden=true;menu.setAttribute('role','group');menu.setAttribute('aria-label','Notification actions');
      const read=action('Mark as read','mail'),archive=action('Archive','archive');read.dataset.npOpRead=String(item.id);archive.dataset.npOpArchive=String(item.id);menu.append(read,archive);end.append(dot,more,menu);row.append(badge,message,end);return row;
    }

    function hydrate(row) {
      const part=s=>row.querySelector(s), menu=part('.np-notification-menu'),end=part('.np-notification-row-actions');
      let dot=part('.np-notification-dot');if(!dot){dot=make('span',undefined,'np-notification-dot');dot.setAttribute('aria-hidden','true');end.insertBefore(dot,end.firstChild);}
      let read=menu.querySelector('[data-np-op-read]');if(!read){read=action('Mark as read','mail');read.dataset.npOpRead=row.dataset.npNotificationId;menu.insertBefore(read,menu.firstChild);}
      return {row,badge:part('.np-notification-icon'),message:part('.np-notification-message'),title:part('.np-notification-title'),summary:part('.np-notification-summary'),target:part('.np-notification-target')||part('.np-notification-meta')?.children[0],time:part('time'),more:part('.np-notification-icon-button'),menu,dot,read,archive:menu.querySelector('[data-np-op-archive]')};
    }
    for(const row of root.querySelectorAll('[data-np-notification-id]')){
      const entry=hydrate(row);
      entry.item={id:Number(row.dataset.npNotificationId),title:entry.title.textContent,summary:entry.summary.textContent,target:entry.target.textContent,created_at:entry.time.dateTime,read_at:row.className.includes('np-notification-unread')?null:'read',issue_id:Number(entry.message.dataset.npNotificationIssue)||0,operation_id:Number(entry.message.dataset.npNotificationOperation)||0};
      rows.set(String(row.dataset.npNotificationId),entry);latest.push(entry.item);
    }

    function update(entry,item) {
      entry.item=item;
      const unread=!item.read_at, stamp=notificationTime(item.created_at,options.now?options.now():Date.now(),options.locale);
      entry.row.className='np-notification-row'+(unread?' np-notification-unread':'');
      entry.title.textContent=item.title;entry.summary.textContent=item.summary;entry.target.textContent=item.target||'Workspace';
      entry.message.setAttribute('aria-label',(unread?'Unread: ':'')+item.title+'. '+(item.target||'Workspace')+'. '+stamp.label);
      const announcement=entry.message.querySelector('.np-sr-only');if(announcement)announcement.hidden=!unread;
      entry.time.textContent=stamp.label;entry.time.dateTime=stamp.datetime;entry.time.title=stamp.title;
      const severity=['warning','critical'].includes(item.severity)?item.severity:'info';entry.badge.className='np-notification-icon np-notification-icon-'+severity;
      entry.badge.replaceChildren(icon(['login_new_device','login_failed_burst'].includes(item.kind)?'shield':severity!=='info'?'triangle-alert':'bell'));
      entry.more.setAttribute('aria-label','Actions for '+item.title);entry.more.title='Actions for '+item.title;
      entry.dot.hidden=!unread;entry.read.hidden=!unread;
      for(const control of [entry.more,entry.read,entry.archive])control.disabled=busy(item.id);
      entry.row.setAttribute('aria-busy',String(busy(item.id)));
    }

    function interacting(){return options.preserveInteraction!==false&&(root.contains(doc.activeElement)||menuID!==null);}
    function render(items,next={identity:options.identity}) {
      if(destroyed||next.identity!==options.identity)return false;
      latest=items||[];context=next;
      if(!next.force&&interacting()){deferred={items:latest,context:next};return false;}
      deferred=null;
      const scroll=root.scrollTop,anchor=[...rows.values()].find(e=>e.row.getBoundingClientRect().bottom>root.getBoundingClientRect().top),anchorTop=anchor?.row.getBoundingClientRect().top;
      const wanted=[],retained=new Set(),now=options.now?options.now():Date.now();let previousDate;
      for(const item of latest){if(!Number.isSafeInteger(Number(item.id))||Number(item.id)<=0||retained.has(String(item.id)))continue;const id=String(item.id);retained.add(id);
        if(options.density!=='compact'){const date=dateGroup(item.created_at,now,options.locale);if(previousDate!==date.key){let heading=dates.get(date.key);if(!heading){heading=make('h2',date.label,'np-notification-date');heading.dataset.npNotificationDate=date.key;dates.set(date.key,heading);}heading.textContent=date.label;wanted.push(heading);previousDate=date.key;}}
        let entry=rows.get(id);if(!entry){entry=hydrate(construct(item));rows.set(id,entry);}update(entry,item);wanted.push(entry.row);
      }
      for(const [id,entry] of rows)if(!retained.has(id)){entry.row.remove();rows.delete(id);}
      if(!wanted.length){const empty=make('div',undefined,'np-notification-empty'),search=!!next.search,unread=next.status==='unread';empty.append(icon('bell'),make('h3',search?'No matching notifications':unread?'All caught up':'No notifications yet'),make('p',search?'Try another title, resource or message.':unread?'You have no unread notifications.':'Account and hosting updates will appear here.'));wanted.push(empty);}
      let cursor=root.firstChild;for(const n of wanted){if(n!==cursor)root.insertBefore(n,cursor);cursor=n.nextSibling;}while(cursor){const nextNode=cursor.nextSibling;cursor.remove();cursor=nextNode;}
      root.scrollTop=scroll;if(anchor&&rows.has(String(anchor.item?.id)))root.scrollTop+=anchor.row.getBoundingClientRect().top-anchorTop;
      return true;
    }
    function flush(){if(deferred){const next=deferred;render(next.items,{...next.context,force:true});}}
    function closeMenu(restore=false){const id=menuID;menuID=null;const entry=rows.get(String(id));if(entry){entry.menu.hidden=true;entry.more.setAttribute('aria-expanded','false');}if(!root.contains(doc.activeElement))flush();if(restore)entry?.more.focus();}
    function placeMenu(entry){const rect=entry.more.getBoundingClientRect(),win=doc.defaultView,height=entry.menu.getBoundingClientRect().height,width=172;entry.menu.style.left=Math.max(12,Math.min(rect.right-width,win.innerWidth-width-12))+'px';entry.menu.style.top=Math.max(12,Math.min(rect.bottom+4,win.innerHeight-height-12,rect.bottom+height+4>win.innerHeight-12?rect.top-height-4:Infinity))+'px';}
    function click(event){const target=event.target.closest?.('button');if(!target||!root.contains(target))return;const row=target.closest('[data-np-notification-id]'),entry=rows.get(row?.dataset.npNotificationId);if(!entry)return;event.preventDefault();event.stopPropagation();
      if(target.dataset.npNotificationMenu){const open=menuID!==String(entry.item.id);closeMenu();if(open){menuID=String(entry.item.id);entry.menu.hidden=false;entry.more.setAttribute('aria-expanded','true');placeMenu(entry);(entry.read.hidden?entry.archive:entry.read).focus();}return;}
      if(target.dataset.npNotificationOpen){options.onOpen?.(entry.item,target);return;}
      const kind=target.dataset.npOpRead?'read':target.dataset.npOpArchive?'archive':null;if(kind&&!busy(entry.item.id))options.onReceipt?.(entry.item.id,kind,target);
    }
    function outside(event){if(!root.contains(event.target))closeMenu();}
    function key(event){if(menuID===null)return;if(event.key==='Escape'){event.preventDefault();event.stopImmediatePropagation();closeMenu(true);}else if(['ArrowDown','ArrowUp','Home','End'].includes(event.key)){const entry=rows.get(menuID),controls=[entry.read,entry.archive].filter(n=>!n.hidden&&!n.disabled),at=controls.indexOf(doc.activeElement);if(controls.length){event.preventDefault();controls[event.key==='Home'?0:event.key==='End'?controls.length-1:(at+(event.key==='ArrowUp'?-1:1)+controls.length)%controls.length].focus();}}}
    root.addEventListener('click',click);doc.addEventListener('click',outside);doc.addEventListener('keydown',key,true);
    return {
      render,flush,closeMenu,items:()=>latest,
      setPending(id,value){if(value)pending.add(String(id));else pending.delete(String(id));for(const entry of rows.values())if(entry.item)update(entry,entry.item);},
      setError(message,retry){
        if(!errorRoot)return;
        const restore=errorRoot.contains(doc.activeElement);
        errorRoot.replaceChildren(make('span',message||''));errorRoot.hidden=!message;
        if(message&&retry){const b=make('button','Retry');b.type='button';b.addEventListener('click',retry);errorRoot.append(b);}
        if(!message&&restore){const target=container?.querySelector('h2')||root.querySelector('.np-notification-message')||root;if(target.tagName.toLowerCase()!=='button')target.tabIndex=-1;target.focus();}
      },
      focusAfter(id,removed=false){const ids=[...root.querySelectorAll('[data-np-notification-id]')].map(n=>n.dataset.npNotificationId),index=ids.indexOf(String(id)),next=removed?ids[index+1]||ids[index-1]:String(id);return ()=>{const e=rows.get(next);if(e)(removed?e.message:e.more).focus();else{const heading=container?.querySelector('h2')||root;heading.tabIndex=-1;heading.focus();}};},
      destroy(){destroyed=true;closeMenu();root.removeEventListener('click',click);doc.removeEventListener('click',outside);doc.removeEventListener('keydown',key,true);}
    };
  }

  const api={notificationTime,notificationPopoverPosition,notificationBadge,notificationPreviewQuery,restoreNotificationFocus,createNotificationView,createNotificationActions,loadNotificationDetail};
  if(typeof module!=='undefined'&&module.exports)module.exports=api;
  if(typeof window!=='undefined')window.NakpanelNotifications=api;
})();
