const {test}=require('node:test');
const assert=require('node:assert/strict');
const {notificationTime,notificationPopoverPosition,notificationBadge,notificationPreviewQuery,createNotificationView}=require('./notifications.js');

test('notification timestamps stay compact and exact time includes a zone',()=>{
 const now=Date.parse('2026-10-28T14:40:00Z');
 for(const [value,label] of [['bad','Unknown time'],['2026-10-28T15:00:00Z','Just now'],['2026-10-28T14:39:30Z','Just now'],['2026-10-28T14:39:00Z','1 min ago'],['2026-10-28T13:40:00Z','1 hr ago'],['2026-10-27T15:40:00Z','23 hr ago']])assert.equal(notificationTime(value,now,'en-GB').label,label);
 assert.match(notificationTime('2026-10-27T14:40:00Z',now,'en-GB').label,/27.*Oct.*2026/);
 assert.match(notificationTime('2026-10-28T14:39:00Z',now,'en-GB').title,/2026/);
 assert.equal(notificationTime('2026-10-28T14:39:00Z',now).datetime,'2026-10-28T14:39:00.000Z');
});
test('preview anchors to a wrapped topbar and stays inside narrow or short viewports',()=>{
 for(const width of [320,390,1440]){const p=notificationPopoverPosition({right:width-20,bottom:104},{width,height:844});assert.equal(p.top,112);assert.equal(p.width,Math.min(400,width-24));assert.ok(p.left>=12&&p.left+p.width<=width-12);assert.ok(p.top+p.maxHeight<=832)}
 const p=notificationPopoverPosition({right:700,bottom:200},{width:720,height:300});assert.equal(p.maxHeight,80);
});
test('badge caps visuals but exposes the exact unread count',()=>{
 assert.deepEqual(notificationBadge(123),{text:'99+',label:'Notifications, 123 unread',hidden:false});
 assert.deepEqual(notificationBadge(0),{text:'',label:'Notifications',hidden:true});
});
test('preview never inherits inbox search, cursor or filters',()=>{
 const q=notificationPreviewQuery('resource_kind=customer&resource_id=10&q=hidden&before=9','unread');
 assert.equal(q.get('limit'),'5');assert.equal(q.get('view'),'inbox');assert.equal(q.get('status'),'unread');assert.equal(q.get('resource_id'),'10');assert.equal(q.has('q'),false);assert.equal(q.has('before'),false);
});

// A minimal tree exercises keyed node identity without introducing a DOM package.
class Element {
 constructor(tag,doc){this.tagName=tag;this.ownerDocument=doc;this.children=[];this.dataset={};this.style={};this.attrs={};this.scrollTop=0;this.className='';this.hidden=false;this.textContent='';}
 append(...nodes){for(const node of nodes)this.insertBefore(node,null)}
 insertBefore(node,before){node.remove();const i=before?this.children.indexOf(before):this.children.length;this.children.splice(i<0?this.children.length:i,0,node);node.parentNode=this}
 remove(){if(this.parentNode){const i=this.parentNode.children.indexOf(this);this.parentNode.children.splice(i,1);this.parentNode=null}}
 replaceChildren(...nodes){this.children.slice().forEach(n=>n.remove());this.append(...nodes)}
 get firstChild(){return this.children[0]||null}get nextSibling(){return this.parentNode?.children[this.parentNode.children.indexOf(this)+1]||null}
 setAttribute(k,v){this.attrs[k]=String(v)}getAttribute(k){return this.attrs[k]??null}
 addEventListener(){}removeEventListener(){}contains(n){return n===this||this.children.some(c=>c.contains(n))}
 querySelectorAll(s){const match=n=>{if(s.startsWith('.'))return n.className.split(' ').includes(s.slice(1));if(s.startsWith('[data-')){const key=s.slice(6,-1).replace(/-([a-z])/g,(_m,c)=>c.toUpperCase());return n.dataset[key]!==undefined;}return n.tagName===s;};return this.children.flatMap(n=>[...(match(n)?[n]:[]),...n.querySelectorAll(s)])}
 querySelector(s){return this.querySelectorAll(s)[0]||null}closest(){return null}
 getBoundingClientRect(){return {top:0,bottom:20,left:0,right:300,width:300,height:20}}
 focus(){this.ownerDocument.activeElement=this}
}
function tree(){const doc={activeElement:null,addEventListener(){},removeEventListener(){},defaultView:{innerWidth:390,innerHeight:844}};doc.createElement=tag=>new Element(tag,doc);doc.createElementNS=(_ns,tag)=>new Element(tag,doc);return new Element('div',doc)}
const notice=(id,title='Message')=>({id,title,summary:'Safe summary',target:'studio.example',created_at:'2026-10-28T14:35:00Z'});
test('keyed rendering preserves focused nodes, scroll and pending state; rejects old identity',()=>{
 const root=tree(),view=createNotificationView(root,{identity:'client:11|sub:42',density:'compact'});
 view.render([notice(1),notice(2)],{identity:'client:11|sub:42'});
 const row=root.querySelectorAll('[data-np-notification-id]')[0],message=row.querySelector('.np-notification-message');root.scrollTop=30;message.focus();
 view.setPending(1,true);view.render([notice(3),notice(1,'Updated'),notice(2)],{identity:'client:11|sub:42'});
 assert.equal(root.querySelectorAll('[data-np-notification-id]')[0],row);assert.equal(root.scrollTop,30);assert.equal(root.ownerDocument.activeElement,message);
 assert.equal(view.render([notice(99)],{identity:'other'}),false);assert.equal(root.querySelectorAll('[data-np-notification-id]').length,2);
 root.ownerDocument.activeElement=null;view.flush();assert.equal(root.querySelectorAll('[data-np-notification-id]')[1],row);assert.equal(row.querySelector('.np-notification-icon-button').disabled,true);
 view.destroy();view.render([notice(100)],{identity:'client:11|sub:42'});assert.equal(root.querySelectorAll('[data-np-notification-id]').length,3);
});
