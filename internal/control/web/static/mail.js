(function () {
  'use strict';
  function mailAddressMatches(address, query) { return String(address).toLowerCase().includes(String(query).trim().toLowerCase()); }
  function createMailConnectionLoader(environment) {
    var generation=0;
    return {load:async function(url){var own=++generation;try{var value=await environment.request(url);if(own===generation)environment.show(value);}catch(error){if(own===generation)environment.error(error);}},stop:function(){generation++;}};
  }
  if(typeof module!=='undefined'&&module.exports)module.exports={mailAddressMatches:mailAddressMatches,createMailConnectionLoader:createMailConnectionLoader};
  if(typeof window==='undefined'||!window.NakpanelUI)return;
  var document=window.document,ui=window.NakpanelUI,dialog=document.getElementById('np-mail-connect-dialog');
  function mount(root){
    root.querySelectorAll('[data-np-mail-protocol-panel="pop"]').forEach(function(panel){panel.hidden=true;});
    root.querySelectorAll('[data-np-mail-client-view]').forEach(function(view){view.classList.add('is-enhanced');});
  }
  mount(document);
  function message(text){
    dialog.replaceChildren();
    var head=document.createElement('div');head.className='np-dialog-head';
    var title=document.createElement('h2');title.id='np-mail-connect-title';title.textContent='Connect a mail app';head.appendChild(title);
    var close=document.createElement('button');close.type='button';close.className='np-secondary-button';close.setAttribute('data-np-dialog-close','');close.textContent='Close';head.appendChild(close);
    var body=document.createElement('p');body.className='np-mail-client-body';body.setAttribute('role','status');body.textContent=text;
    dialog.append(head,body);
  }
  var loader=createMailConnectionLoader({request:async function(url){
    var controller=new AbortController(),timer=setTimeout(function(){controller.abort();},12000);
    try{
      var response=await ui.fetch(url,{headers:{'X-Nakpanel-Mail':'connection','Accept':'text/html'},signal:controller.signal});
      var html=await response.text(),parsed=new DOMParser().parseFromString(html,'text/html'),content=parsed.querySelector('[data-np-mail-client-view]');
      if(!content)throw new Error('Connection settings could not be loaded. Refresh this page and sign in again if needed.');
      return content;
    }finally{clearTimeout(timer);}
  },show:function(content){if(!dialog.open)return;dialog.replaceChildren(document.importNode(content,true));mount(dialog);var close=dialog.querySelector('[data-np-dialog-close]');if(close)close.focus();},error:function(error){if(dialog.open)message(error.name==='AbortError'?'The mail service check timed out. Close this dialog and try again.':error.message);}});
  if(dialog)dialog.addEventListener('close',function(){loader.stop();});
  document.addEventListener('input',function(event){
    if(!event.target.matches('[data-np-mail-search]'))return;
    var root=event.target.closest('[data-np-mail-list]'),visible=0;
    root.querySelectorAll('[data-np-mail-row]').forEach(function(row){var matched=mailAddressMatches(row.dataset.npMailRow,event.target.value);row.hidden=!matched;if(matched)visible++;});
    var empty=root.querySelector('[data-np-mail-no-results]'),count=root.querySelector('[data-np-mail-count]');if(empty)empty.hidden=visible!==0;if(count)count.textContent=visible+' email addresses';
  });
  document.addEventListener('click',async function(event){
    var link=event.target.closest('[data-np-mail-connect]');
    if(link&&dialog&&ui.dialogs&&!event.ctrlKey&&!event.metaKey&&!event.shiftKey&&event.button===0){
      var url=new URL(link.href,window.location.href);
      if(url.origin!==window.location.origin||! /^(\/support\/customers\/\d+)?\/sites\/\d+$/.test(url.pathname))return;
      event.preventDefault();loader.stop();message('Checking secure IMAP and SMTP connections...');ui.dialogs.open(dialog,link);loader.load(url.href);return;
    }
    var settings=event.target.closest('[data-np-mail-settings]');
    if(settings&&ui.dialogs&&!event.ctrlKey&&!event.metaKey){var target=document.getElementById(settings.dataset.npMailSettings);if(target){event.preventDefault();ui.dialogs.open(target,settings);}return;}
    var protocol=event.target.closest('[data-np-mail-protocol]');
    if(protocol){var root=protocol.closest('[data-np-mail-client-view]'),selected=protocol.dataset.npMailProtocol;root.querySelectorAll('[data-np-mail-protocol]').forEach(function(tab){var active=tab===protocol;tab.setAttribute('aria-selected',String(active));tab.tabIndex=active?0:-1;});root.querySelectorAll('[data-np-mail-protocol-panel]').forEach(function(panel){panel.hidden=panel.dataset.npMailProtocolPanel!==selected;});return;}
    var direction=event.target.closest('[data-np-mail-direction]');
    if(direction){var root=direction.closest('[data-np-mail-client-view]');root.dataset.npMailDirection=direction.dataset.npMailDirection;root.querySelectorAll('[data-np-mail-direction]').forEach(function(button){button.setAttribute('aria-pressed',String(button===direction));});return;}
    var copy=event.target.closest('[data-np-mail-copy]');
    if(copy){var root=copy.closest('[data-np-mail-client-view]'),status=root.querySelector('[data-np-mail-copy-status]'),manual=root.querySelector('[data-np-mail-manual-copy]'),value=copy.dataset.npMailCopy;
      if(!value||value.length>4096)return;
      try{await window.navigator.clipboard.writeText(value);status.textContent='Copied. No password is included.';manual.hidden=true;}
      catch(_){manual.value=value;manual.hidden=false;manual.focus();manual.select();status.textContent='Clipboard unavailable. Select and copy these settings manually.';}
    }
  });
  document.addEventListener('keydown',function(event){
    var tab=event.target.closest('[data-np-mail-protocol]');if(!tab||!['ArrowLeft','ArrowRight','Home','End'].includes(event.key))return;
    event.preventDefault();var tabs=Array.from(tab.parentElement.querySelectorAll('[data-np-mail-protocol]')),next=(event.key==='Home')?tabs[0]:(event.key==='End')?tabs[tabs.length-1]:tabs[(tabs.indexOf(tab)+1)%tabs.length];next.click();next.focus();
  });
})();
