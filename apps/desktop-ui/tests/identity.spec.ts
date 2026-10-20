import{test,expect}from'@playwright/test';
test('identity activity is lazy, five rows per page, filtered before pagination, with separate raw evidence',async({page})=>{
 await page.addInitScript(()=>{
  const calls:string[]=[];Object.defineProperty(window,'__PIKO_IDENTITY_CALLS__',{value:calls});Object.defineProperty(window,'isTauri',{value:true});
  const event=(n:number)=>({schema_version:1,event_id:`event-${n}`,host_id:'host',boot_id:null,runtime_instance_id:'runtime',sensor_id:'windows.event_log.Security',sequence:n,wall_clock_time:1000,monotonic_time:1,observation_time:1000,ingestion_time:1000,event_category:'windows_event_log',event_type:'windows.event_log.4648',severity:'info',actor_identity:null,logon_session:null,process:null,parent_process:null,target:{kind:'windows_event_record',identifier:`Security:Microsoft-Windows-Security-Auditing:${n}`},operation:'observe',result:'recorded_by_windows',causal_parents:[],correlation_ids:[],raw_evidence_reference:`raw-${n}`,integrity_metadata:{normalization_version:1,source_integrity:null}});
  Object.defineProperty(window,'__TAURI_INTERNALS__',{value:{invoke:async(command:string,args?:{filter?:{before_position:number|null;kind:string|null;limit:number};evidenceId?:string})=>{
   calls.push(command);
   if(command==='get_health')return{product:'piko',version:'0.2.0',protection_state:'limited',runtime_mode:'windows_service',uptime_seconds:1,stored_events:6,queue_depth:0,dropped_events:0,sensors:[]};
   if(command==='list_events'||command==='list_alerts')return[];
   if(command==='process_actions')return[];
   if(command==='get_observations')return{started_at_unix_ms:Date.now(),completed_at_unix_ms:Date.now(),process_complete:true,network_complete:true,udp_complete:true,warnings:[],processes:[],connections:[],udp_endpoints:[]};
   if(command==='authentication_activity'){
    if(args?.filter?.kind==='failed_logon')return{records:[],next_before:null};
    const older=args?.filter?.before_position!==null;const entries=older?[1]:[6,5,4,3,2];
    return{records:entries.map(n=>({position:n,kind:'explicit_credentials',event:event(n),context:{evidence_status:'verified',account:{name:`alice-${n}`,domain:'PC',sid:null},subject:{name:null,domain:null,sid:null},logon_type:null,logon_id:'0x3e7',address:'192.0.2.10',workstation:null,caller_path:'C:\\Windows\\System32\\svchost.exe',caller_pid:42,target_server:'server',authentication_package:null,privileges:[]}})),next_before:older?null:2};
   }
   if(command==='get_evidence')return{evidence_id:args?.evidenceId,source:'windows.event_log.Security',content_type:'application/xml; charset=utf-8',observed_at_unix_ms:1000,bytes:Array.from(new TextEncoder().encode('<Event>identity fixture</Event>'))};
   throw Error(`Unexpected command ${command}`);
  }}});
 });
 await page.goto('/');await page.locator('.sidebar nav').getByRole('button',{name:'Attività applicazioni',exact:true}).click();
 expect(await page.evaluate(()=>((window as unknown as{__PIKO_IDENTITY_CALLS__:string[]}).__PIKO_IDENTITY_CALLS__).filter(c=>c==='authentication_activity'))).toHaveLength(0);
 const panel=page.locator('.identity-activity');await panel.locator('summary').first().click();await expect(panel.locator('.content>ul>li')).toHaveCount(5);
 await panel.getByRole('button',{name:'Più vecchi',exact:true}).click();await expect(panel.locator('.content>ul>li')).toHaveCount(1);await expect(panel.getByText('PC\\alice-1',{exact:true})).toBeVisible();
 await panel.getByRole('button',{name:'Più recenti',exact:true}).click();await expect(panel.locator('.content>ul>li')).toHaveCount(5);
 await panel.locator('.record-details>summary').first().click();const detail=panel.locator('.record-details[open]');await expect(detail.getByText('svchost.exe · PID 42',{exact:false})).toBeVisible();await expect(detail.getByText('Questo evento non conferma',{exact:false})).toBeVisible();
 await panel.getByRole('button',{name:'Apri evento e dati grezzi'}).first().click();await expect(page.getByRole('dialog')).toBeVisible();
 await page.getByRole('dialog').getByRole('button',{name:'Leggi evidenza originale',exact:true}).click();await expect(page.locator('.source-evidence')).toContainText('identity fixture');
 await page.getByRole('dialog').getByRole('button',{name:'Chiudi',exact:true}).click();await panel.getByLabel('Categoria accessi',{exact:true}).selectOption('failed_logon');await expect(panel.locator('.content>ul>li')).toHaveCount(0);await expect(panel.getByText('Non dimostra assenza di accessi',{exact:false})).toBeVisible();
 const journal=page.locator('.process-journal');await journal.locator('summary').first().click();await expect(journal.getByText('Nessuna operazione registrata.',{exact:true})).toBeVisible();
});
