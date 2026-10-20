import { test,expect,type Page } from '@playwright/test';
// Synthetic data is confined to tests; native production imports no example feed.
async function bridge(page:Page,mode:'empty'|'matched'|'stale'='matched') {
  await page.addInitScript(({mode})=>{
    const product={product_id:'test:legacy-editor',display_name:'Test legacy editor',covered_versions:['1.0','2.0']};
    const advisory={id:'TEST-LEGACY-1',product_id:product.product_id,affected_versions:['1.0'],kind:'vulnerability',title:'Synthetic document parser issue',summary:'Test-only advisory for the legacy editor.',cvss_x100:750,cvss_version:'3.1',cvss_vector:'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',source_url:'https://example.org/TEST-LEGACY-1',published_at:99,remediation:['Test-only: block network access','Test-only: open documents in a sandbox']};
    const app={id:'test-legacy',display_name:'Legacy Editor (test)',publisher:'Test vendor',version:'1.0',install_location:null,install_date:null,display_icon:null,scope:'user',registry_view:'native',source:'windows_uninstall_registry',uninstall_key:'test-key'};
    const binding={application_id:app.id,application_name:app.display_name,publisher:app.publisher,installer_version:app.version,product_id:product.product_id,exact_version:'1.0',bound_at:120};
    let current={checked_at:mode==='stale'?250:150,inventory_complete:true,unbound_count:mode==='empty'?1:0,feed:mode==='empty'?null:{source_name:'Synthetic test-only feed',source_url:'https://example.org/advisories',generated_at:100,expires_at:200,imported_at:120,sha256:'a'.repeat(64),advisory_count:1,product_count:1,products:[product],stale:mode==='stale',authenticity:'not_verified'},entries:mode==='empty'?[]:[{binding,state:'matched',advisory_count:1}],advisories:mode==='empty'?[]:[advisory]};
    const calls:{command:string,args?:Record<string,unknown>}[]=[];
    Object.defineProperty(window,'isTauri',{value:true});Object.defineProperty(window,'__ADVISORY_CALLS__',{value:calls});
    Object.defineProperty(window,'__TAURI_INTERNALS__',{value:{invoke:async(command:string,args?:Record<string,unknown>)=>{
      calls.push({command,args});
      if(command==='get_health')return {product:'piko',version:'0.2.0',protection_state:'degraded',runtime_mode:'development_console',uptime_seconds:60,stored_events:0,queue_depth:0,dropped_events:0,sensors:[]};
      if(['list_alerts','list_events','list_alert_reviews'].includes(command))return [];
      if(command==='software_inventory')return {entries:[app],complete:true,truncated:false,warnings:[]};
      if(command==='network_snapshot')return {active_profiles:2,local_policy_modify_state:'ok',complete:true,warnings:[],rules:[],profiles:[1,2,4].map(id=>({id,name:({1:'domain',2:'private',4:'public'}as Record<number,string>)[id],active:id===2,firewall_enabled:true,block_all_inbound:false,excluded_interfaces:false}))};
      if(command==='advisory_status')return current;
      if(command==='import_advisory_feed'){const f=JSON.parse(String(args?.json));if(f.schema_version!==1)throw new Error('Invalid test feed'); current={...current,feed:{source_name:f.source_name,source_url:f.source_url,generated_at:100,expires_at:200,imported_at:120,sha256:'b'.repeat(64),advisory_count:1,product_count:1,products:[product],stale:false,authenticity:'not_verified'},advisories:[advisory]};return null;}
      if(command==='bind_advisory_product'){current={...current,unbound_count:0,entries:[{binding:{...binding,exact_version:String(args?.exactVersion)},state:args?.exactVersion==='1.0'?'matched':'no_known_advisory',advisory_count:args?.exactVersion==='1.0'?1:0}]};return null;}
      if(command==='unbind_advisory_product'){current={...current,entries:[],unbound_count:1};return null;}
      throw new Error('Unsupported fixture command '+command);
    }}});
  },{mode});
  await page.goto('/');await page.getByRole('button',{name:'Permessi app',exact:true}).click();
  const panel=page.getByTestId('software-advisories');await panel.locator('>summary').click();return panel;
}
test('advisory details keep source index, mitigations and provenance explicit',async({page})=>{
  const panel=await bridge(page);await expect(panel.getByText('Synthetic test-only feed',{exact:true})).toBeVisible();
  await panel.getByRole('button',{name:/Legacy Editor \(test\)/}).click();
  await expect(panel.getByText('CVSS 3.1 7.5/10',{exact:true})).toBeVisible();
  await panel.getByText('Azioni suggerite e fonte',{exact:true}).click();await expect(panel.getByText('Test-only: block network access',{exact:true})).toBeVisible();
  await panel.getByText('Fonte e copertura',{exact:true}).click();await expect(panel.getByText(/Piko non verifica una firma del feed/)).toBeVisible();
  await panel.getByRole('button',{name:'Rimuovi associazione',exact:true}).click();await expect(panel.getByText('Associazione rimossa.',{exact:true})).toBeVisible();
});
test('empty configuration imports a feed then requires explicit product binding',async({page})=>{
  const panel=await bridge(page,'empty');await expect(panel.getByText(/Nessun feed configurato/)).toBeVisible();
  await panel.locator('input[type=file]').setInputFiles({name:'invalid-test.json',mimeType:'application/json',buffer:Buffer.from('{}')});await expect(panel.getByRole('alert')).toContainText('Invalid test feed');
  await panel.locator('input[type=file]').setInputFiles({name:'synthetic-test-only.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify({schema_version:1,source_name:'Synthetic test-only feed',source_url:'https://example.org/advisories'}))});
  await expect(panel.getByText('Feed importato. La provenienza non è autenticata da piko.',{exact:true})).toBeVisible();await panel.getByRole('button',{name:'Associa applicazione',exact:true}).click();
  await panel.getByRole('combobox',{name:'Applicazione osservata (primi 50 risultati)',exact:true}).selectOption('test-legacy');await panel.getByRole('combobox',{name:'Prodotto nel feed',exact:true}).selectOption('test:legacy-editor');
  const save=panel.getByRole('button',{name:'Salva associazione',exact:true});await expect(save).toBeDisabled();await panel.getByRole('checkbox').check();await expect(save).toBeEnabled();await save.click();
  await panel.getByRole('button',{name:/Legacy Editor \(test\)/}).click();await expect(panel.getByText('CVSS 3.1 7.5/10',{exact:true})).toBeVisible();
});
test('expired data retains findings and warns without claiming current coverage',async({page})=>{
  const panel=await bridge(page,'stale');await expect(panel.getByText(/Feed scaduto: gli avvisi restano visibili/)).toBeVisible();await panel.getByRole('button',{name:/Legacy Editor \(test\)/}).click();await expect(panel.getByText('Synthetic document parser issue',{exact:true})).toBeVisible();
});
