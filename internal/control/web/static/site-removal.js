(function () {
  'use strict';
  function createSiteRemovalController(environment) {
    var submitted = false, stopped = false, progressURL = '', generation = 0;
    function update(value) { environment.update(value); }
    function safeDestination(path) {
      try {
        var url = new URL(path, environment.baseURL), base = new URL(environment.baseURL);
        return url.origin === base.origin && /^(\/support\/customers\/\d+)?\/(sites|subscriptions)\/\d+$/.test(url.pathname);
      } catch (_) { return false; }
    }
    async function watch(statusURL, pageURL) {
      stopped = false; progressURL = pageURL; var own = ++generation, start = environment.now(), delay = 2000;
      while (!stopped && own === generation && environment.now() - start < 300000) {
        var result;
        try { result = await environment.request(statusURL); }
        catch (error) {
          update({state: error.status === 401 ? 'signin' : 'uncertain', message: error.status === 404 ? 'Removal status was not found in your workspace.' : error.message, progress_url: progressURL});
          return;
        }
        if (stopped || own !== generation) return;
        update(result);
        if (result.state === 'completed') {
          if (result.redirect && safeDestination(result.redirect)) environment.redirect(result.redirect);
          return;
        }
        if (result.state === 'failed') return;
        await environment.sleep(Math.min(delay,Math.max(0,300000-(environment.now()-start)))); delay = Math.min(10000, delay + 1000);
      }
      if (!stopped && own === generation) update({state:'background',message:'Removal is continuing in the background. Check its progress before creating a replacement.',progress_url:progressURL});
    }
    async function check(lookupURL) {
      var result;
      try { result = await environment.request(lookupURL); }
      catch (error) { update({state:error.status===401?'signin':'uncertain',message:error.status===404?'No accepted removal was found. Review the website before making another request.':error.message,progress_url:progressURL}); return; }
      update(result);
      if (result.status_url) await watch(result.status_url,result.progress_url);
    }
    async function submit(url,body,lookupURL) {
      if (submitted) return;
      submitted = true; var result,own=generation;
      try { result = await environment.request(url,{method:'POST',body:body}); }
      catch (error) {
        if(stopped||own!==generation)return;
        if (error.status === 400 || error.status === 403 || error.status === 404) {
          submitted = false; update({state:'validation',message:error.message,refresh_preview:!!(error.payload&&error.payload.refresh_preview)}); return;
        }
        update({state:error.status===401?'signin':'uncertain',message:'The request may already have been accepted. Check removal status; do not submit it again.'});
        if (error.status !== 401) await check(lookupURL);
        return;
      }
      if(stopped||own!==generation)return;
      update(result);
      if (result.status_url) await watch(result.status_url,result.progress_url);
    }
    return {submit:submit,check:check,watch:watch,stop:function(){stopped=true;generation++;}};
  }
  if (typeof module !== 'undefined' && module.exports) module.exports = {createSiteRemovalController:createSiteRemovalController};
  if (typeof window === 'undefined' || !window.NakpanelUI) return;
  var ui = window.NakpanelUI, document = window.document, dialog = document.getElementById('np-site-removal-dialog');
  var controllers = new WeakMap();
  async function request(url,options) {
    var controller=new AbortController(), timer=setTimeout(function(){controller.abort();},10000);
    options=Object.assign({},options||{});
    if(options.body&&typeof options.body.get==='function'&&options.body.get('csrf_token'))options.headers={'X-Nakpanel-CSRF':options.body.get('csrf_token')};
    try {var response=await ui.fetch(url,Object.assign({},options,{signal:controller.signal}));return await response.json();}
    finally {clearTimeout(timer);}
  }
  function mount(root) {
    var signature='';
    var controller=createSiteRemovalController({baseURL:window.location.href,request:request,now:Date.now,sleep:function(ms){return new Promise(function(resolve){setTimeout(resolve,ms);});},redirect:function(path){window.location.assign(path);},update:function(value){
      if (value.html && signature!==value.state+':'+value.stage) {root.innerHTML=value.html;signature=value.state+':'+value.stage;}
      var error=root.querySelector('[data-np-removal-error]'), recovery=root.querySelector('[data-np-removal-recovery]'), form=root.querySelector('[data-np-removal-form],[data-np-removal-retry]');
      if (value.message && error && ['validation','signin','uncertain','background'].includes(value.state)) {error.textContent=value.message;error.hidden=false;}
      if (recovery && ['signin','uncertain'].includes(value.state)) recovery.hidden=false;
      if(value.refresh_preview){var refresh=root.querySelector('[data-np-removal-refresh]');if(refresh)refresh.hidden=false;}
      if (form) {
        ui.setBusy(form,!['validation','failed'].includes(value.state)||!!value.refresh_preview);
        if(value.refresh_preview)form.dataset.npRemovalStale='true';
        if (['signin','uncertain'].includes(value.state)) form.dataset.npRemovalUncertain='true';
        if (value.state==='validation') {var target=form.querySelector('[name="confirm_domain"]');if(target)target.focus();}
      }
      if (window.NakpanelDomains) window.NakpanelDomains.updateRemovalGate(root);
      if (value.progress_url) root.dataset.npRemovalProgressURL=value.progress_url;
      if (value.state==='background' && root.querySelector('[data-np-removal-message]')) root.querySelector('[data-np-removal-message]').textContent=value.message;
    }});
    controllers.set(root,controller);
    if (window.NakpanelDomains) window.NakpanelDomains.updateRemovalGate(root);
    return controller;
  }
  function rootFor(element){return element.closest('.np-site-removal-dialog,.np-removal-page');}
  document.addEventListener('click',async function(event){
    var link=event.target.closest('[data-np-removal-open]');
    if(link && dialog && ui.dialogs){
      event.preventDefault();var menu=link.closest('details'),opener=menu?menu.querySelector('summary'):link;if(menu)menu.open=false;
      var previousInput=dialog.open&&dialog.querySelector('[name="confirm_domain"]'),previousValue=previousInput?previousInput.value:null;
      var previous=controllers.get(dialog);if(previous)previous.stop();
      dialog.innerHTML='<div class="np-dialog-head"><h2 id="np-site-removal-title">Review removal</h2><button class="np-icon-button" type="button" data-np-dialog-close aria-label="Close"><svg class="np-icon" aria-hidden="true"><use href="/assets/icons.svg#x"></use></svg></button></div><div class="np-removal-body" role="status">Loading the exact domain impact...</div>';
      ui.dialogs.open(dialog,opener);
      try {var result=await request(link.href+'/preview');if(dialog.open){dialog.innerHTML=result.html;var confirm=dialog.querySelector('[name="confirm_domain"]');if(confirm&&previousValue!==null)confirm.value=previousValue;var current=mount(dialog);var input=dialog.querySelector('[data-np-autofocus]');if(input)input.focus();if(result.status_url)current.watch(result.status_url,result.progress_url);}}
      catch(error){var body=dialog.querySelector('.np-removal-body');if(body)body.textContent=error.status===404?'This website is not available in your workspace.':error.message;}
      return;
    }
    var check=event.target.closest('[data-np-removal-check]');if(check){event.preventDefault();var root=rootFor(check),controller=controllers.get(root)||mount(root);await controller.check(check.href);}
  });
  document.addEventListener('submit',async function(event){
    var form=event.target.closest('[data-np-removal-form],[data-np-removal-retry]');if(!form)return;
    event.preventDefault();if(form.dataset.npRemovalUncertain==='true'||form.dataset.npRemovalStale==='true')return;
    var root=rootFor(form),controller=controllers.get(root)||mount(root),body=new URLSearchParams(new FormData(form));
    var lookup=form.dataset.npRemovalLookup || root.dataset.npRemovalProgressURL;
    if(form.hasAttribute('data-np-removal-retry')) {var prior=controllers.get(root);if(prior)prior.stop();controller=mount(root);}
    ui.setBusy(form,true);await controller.submit(form.action,body,lookup);
  });
  if(dialog)dialog.addEventListener('close',function(){var controller=controllers.get(dialog);if(controller)controller.stop();});
  document.querySelectorAll('[data-np-removal-progress]').forEach(function(root){mount(root).watch(root.dataset.npRemovalStatus,window.location.pathname);});
})();
