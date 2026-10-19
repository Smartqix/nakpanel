(function () {
  'use strict';
  function matchesBackup(domain,text,query,selected) {return (!selected||domain===selected)&&(domain+' '+text).toLowerCase().includes((query||'').toLowerCase());}
  function backupStateSignature(states) {return Object.keys(states).sort().map(function(id){return id+':'+states[id];}).join('|');}
  function backupPending(states) {return Object.values(states).some(function(s){return s==='pending'||s==='deleting';});}
  function backupOperationMessage(removing,states,ids){
    if(removing){
      if(ids.every(function(id){return !Object.hasOwn(states,id);}))return 'Selected backups removed. Other recovery points were preserved.';
      if(ids.some(function(id){return states[id]==='delete_failed';}))return 'A selected backup could not be removed. Review its error before retrying.';
      return 'Removing the selected backups. Other recovery points are preserved.';
    }
    if(states[ids[0]]==='active')return 'Backup created. The recovery point is ready.';
    if(states[ids[0]]==='failed')return 'Backup creation failed. Review the recovery point error.';
    return 'Creating your backup. This list updates automatically.';
  }
  if(typeof module!=='undefined'&&module.exports)module.exports={matchesBackup:matchesBackup,backupStateSignature:backupStateSignature,backupPending:backupPending,backupOperationMessage:backupOperationMessage};
  if(typeof window==='undefined'||!window.NakpanelUI)return;
  var ui=window.NakpanelUI,document=window.document,dialog=document.getElementById('np-backup-removal-dialog'),timer,previewGeneration=0,watching=false,started=0;
  function manager(){return document.querySelector('[data-np-backup-manager]');}
  function managerURL(){var url=new URL(window.location.href);url.searchParams.set('tab','backups');url.searchParams.delete('notice');url.hash='';return url;}
  function showError(form,message){var node=form.querySelector('[data-np-backup-error]');if(!node){node=document.createElement('p');node.className='np-error';node.setAttribute('role','alert');form.append(node);}node.textContent=message;node.hidden=false;}
  function announce(message){var root=manager(),node=root&&root.querySelector('[data-np-backup-progress]');if(node){node.textContent=message;node.hidden=false;}}
  function filter(){
    var root=manager();if(!root)return;
    var q=root.querySelector('[data-np-backup-search]').value,domain=root.querySelector('[data-np-backup-domain]').value,count=0,selected=0,available=0;
    root.querySelectorAll('[data-np-backup-row]').forEach(function(row){
      row.hidden=!matchesBackup(row.dataset.backupDomain,row.textContent,q,domain);
      var box=row.querySelector('[data-np-backup-check]');if(row.hidden)box.checked=false;
      if(!row.hidden){count++;if(!box.disabled)available++;if(box.checked)selected++;}
    });
    root.querySelector('[data-np-backup-remove-selected]').disabled=selected===0;
    root.querySelector('[data-np-backup-selection-count]').textContent=selected+' selected';
    var all=root.querySelector('[data-np-backup-select-all]');if(all){all.checked=selected>0&&selected===available;all.indeterminate=selected>0&&selected<available;}
    var empty=root.querySelector('[data-np-backup-no-results]');if(empty)empty.hidden=count>0;
  }
  async function request(url,options){
    var controller=new AbortController(),timeout=setTimeout(function(){controller.abort();},15000);
    try{return await(await ui.fetch(url,Object.assign({},options||{},{signal:controller.signal}))).json();}finally{clearTimeout(timeout);}
  }
  async function preview(url,opener){
    var own=++previewGeneration,owner=manager();
    try{var result=await request(url);if(own!==previewGeneration||!owner||!owner.isConnected)return;dialog.innerHTML=result.html;ui.dialogs.open(dialog,opener);}catch(error){if(own===previewGeneration&&owner&&owner.isConnected)announce(error.message||'Could not load confirmation. No backups were removed.');}
  }
  async function refresh(){
    var root=manager();if(!root||document.querySelector('dialog[open]')||root.contains(document.activeElement)&&document.activeElement.matches('input,select,summary'))return;
    var url=managerURL(),query=root.querySelector('[data-np-backup-search]').value,domain=root.querySelector('[data-np-backup-domain]').value;
    var selected=Array.from(root.querySelectorAll('[data-np-backup-check]:checked')).map(function(b){return b.value;});
    var response=await window.fetch(url.href,{credentials:'same-origin',cache:'no-store',headers:{Accept:'text/html'}});if(!response.ok)throw new Error('Unable to refresh backups.');
    var parsed=new DOMParser().parseFromString(await response.text(),'text/html'),next=parsed.querySelector('[data-np-backup-manager]');if(!root.isConnected||new URL(window.location.href).pathname!==url.pathname)return;if(!next)throw new Error('Sign in again to check backup progress.');
    root.replaceWith(next);
    var oldDialog=document.getElementById('np-backup-create-dialog'),nextDialog=parsed.querySelector('#np-backup-create-dialog');if(oldDialog&&nextDialog)oldDialog.replaceWith(nextDialog);
    next.querySelector('[data-np-backup-search]').value=query;next.querySelector('[data-np-backup-domain]').value=domain;
    next.querySelectorAll('[data-np-backup-check]').forEach(function(b){b.checked=selected.includes(b.value)&&!b.disabled;});filter();
    var currentTab=document.querySelector('.np-subscription-tabs a.is-active'),newTab=parsed.querySelector('.np-subscription-tabs a.is-active');if(currentTab&&newTab)currentTab.replaceWith(newTab);
  }
  async function poll(){
    clearTimeout(timer);var root=manager();if(!root||!watching)return;
    if(Date.now()-started>300000){watching=false;announce('The operation is continuing in the background. Refresh this page to check its result.');return;}
    if(!document.hidden&&!document.querySelector('dialog[open]')){
      try{await refresh();root=manager();if(!root)return;if(!root.querySelector('[data-backup-status="pending"],[data-backup-status="deleting"]')){watching=false;announce('Backup list updated. Check the status of your recovery points.');return;}}catch(error){watching=false;announce(error.message);return;}
    }
    timer=setTimeout(poll,3000);
  }
  function start(){clearTimeout(timer);filter();var root=manager();watching=!!(root&&root.querySelector('[data-backup-status="pending"],[data-backup-status="deleting"]'));if(watching){started=Date.now();timer=setTimeout(poll,1500);}}
  document.addEventListener('input',function(e){if(e.target.matches('[data-np-backup-search]'))filter();});
  document.addEventListener('change',function(e){
    if(e.target.matches('[data-np-backup-select-all]')){var root=manager();if(root)root.querySelectorAll('[data-np-backup-row]:not([hidden]) [data-np-backup-check]:not(:disabled)').forEach(function(b){b.checked=e.target.checked;});}
    if(e.target.matches('[data-np-backup-select-all],[data-np-backup-check],[data-np-backup-domain]'))filter();
  });
  document.addEventListener('click',function(e){
    var link=e.target.closest('[data-np-backup-remove]');if(link&&!e.ctrlKey&&!e.metaKey){e.preventDefault();preview(link.href,link);}
    var cancel=e.target.closest('[data-np-backup-cancel]');if(cancel&&cancel.closest('dialog')){e.preventDefault();ui.dialogs.close(cancel.closest('dialog'));}
  });
  document.addEventListener('submit',async function(e){
    var form=e.target;
    if(form.matches('[data-np-backup-selection]')){e.preventDefault();var url=new URL(form.action);new FormData(form).forEach(function(v,k){url.searchParams.append(k,v);});if(url.searchParams.has('backup_id'))preview(url.href,form.querySelector('button'));return;}
    if(!form.matches('[data-np-backup-remove-form],[data-np-backup-create-form]'))return;
    e.preventDefault();if(form.dataset.busy==='true')return;var owner=manager();form.dataset.busy='true';ui.setBusy(form,true);
    try{
      var submitted=new URLSearchParams(new FormData(form)),removing=form.matches('[data-np-backup-remove-form]');
      var result=await request(form.action,{method:'POST',body:submitted});if(owner&&!owner.isConnected)return;
      var parent=form.closest('dialog');if(parent)ui.dialogs.close(parent);
      if(!manager()){window.location.assign(result.redirect);return;}
      await refresh();start();var states={};manager().querySelectorAll('[data-np-backup-row]').forEach(function(row){states[row.dataset.backupId]=row.dataset.backupStatus;});
      announce(backupOperationMessage(removing,states,removing?submitted.getAll('backup_id'):[String(result.backup_id)]));
    }catch(error){showError(form,error.message||'The request may have been accepted. Close this dialog and refresh the backup list before retrying.');if(!error.status||error.status>=500){form.dataset.uncertain='true';return;}}finally{if(!form.dataset.uncertain){form.dataset.busy='false';ui.setBusy(form,false);}}
  });
  document.addEventListener('nakpanel:navigated',start);
  document.addEventListener('visibilitychange',function(){if(!document.hidden&&watching)poll();});
  start();
}());
