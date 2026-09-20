(function(){
  var stored=null;
  try{stored=localStorage['ptxray-theme'];}catch(e){}
  function sys(){
    return matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';
  }
  function resolved(){
    return (stored==='light'||stored==='dark')?stored:sys();
  }
  function labelFor(t){return t==='dark'?'Light':'Dark';}
  function apply(){
    var t=resolved();
    document.documentElement.dataset.theme=t;
    var b=document.querySelector('.theme-toggle');
    if(b) b.textContent=labelFor(t);
  }
  apply();
  if(stored!=='light'&&stored!=='dark'){
    try{
      matchMedia('(prefers-color-scheme: dark)').addEventListener('change',function(){
        if(stored!=='light'&&stored!=='dark') apply();
      });
    }catch(e){}
  }
  function go(){var h=location.hash.slice(1);if(!h)return;var el=document.getElementById(h);if(!el)return;
  var d=el.closest("details");while(d){d.open=true;d=d.parentElement&&d.parentElement.closest("details");}
  el.scrollIntoView({block:"start"});}
  function bind(){
    var b=document.querySelector('.theme-toggle');
    if(b){
      b.textContent=labelFor(document.documentElement.dataset.theme||resolved());
      b.addEventListener('click',function(){
        var next=document.documentElement.dataset.theme==='dark'?'light':'dark';
        document.documentElement.dataset.theme=next;
        stored=next;
        try{localStorage['ptxray-theme']=next;}catch(e){}
        b.textContent=labelFor(next);
      });
    }
    addEventListener("hashchange",go);go();
  }
  if(document.readyState==='loading') addEventListener('DOMContentLoaded',bind);
  else bind();
})();
