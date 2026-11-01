'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {chromium}=require('playwright');
const base=process.env.APPEARANCE_BASE_URL;
const output=process.env.APPEARANCE_OUTPUT_DIR;
const fixture=process.env.APPEARANCE_FIXTURE_DIR;
assert(base&&/^http:\/\/127\.0\.0\.1:\d+$/.test(base),'HOMEPAGE_APPEARANCE_LOOPBACK_REQUIRED');
const expected=JSON.parse(fs.readFileSync(path.join(fixture,'expected.json'),'utf8'));
(async()=>{
 const browser=await chromium.launch({headless:true,args:['--no-sandbox']});
 let page;
 const results={status:'RUNNING',real_homepage_version:'v2.7.0',viewports:[],service_links:0,visible_container_rows:0};
 try{
  const context=await browser.newContext({viewport:{width:1600,height:1000},deviceScaleFactor:1,colorScheme:'dark'});
  await context.route('**/*',route=>{const u=route.request().url();return u.startsWith(base+'/')||u.startsWith('data:')?route.continue():route.abort();});
  page=await context.newPage();
  await page.goto(base,{waitUntil:'domcontentloaded',timeout:60000});
  await page.waitForSelector('li[data-name="AIOStreams"] .service-icon',{timeout:60000});
  await page.waitForFunction(()=>document.body.textContent.includes('fixture-worker-5')&&document.body.textContent.includes('Isolated appearance CPU'),null,{timeout:60000});
  await page.evaluate(async()=>{
   const background=document.getElementById('background');if(!background)throw Error('BACKGROUND_MISSING');
   const value=getComputedStyle(background).backgroundImage;
   const match=value.match(/url\(["']?(data:image\/[^"')]+)["']?\)/);if(!match)throw Error('BACKGROUND_DATA_IMAGE_MISSING');
   await new Promise((resolve,reject)=>{const image=new Image();image.onload=()=>image.naturalWidth===1600&&image.naturalHeight===900?resolve():reject(Error('BACKGROUND_WRONG_SIZE'));image.onerror=()=>reject(Error('BACKGROUND_DECODE_FAILED'));image.src=match[1];});
  });
  const completion=page.getByText('Da completare',{exact:true});
  if(await completion.count()){
   const visibleLinks=await page.locator('a[href^="https://example.invalid/service/"]').evaluateAll(items=>Array.from(new Set(items.map(item=>item.href))));
   if(visibleLinks.length<expected.link_count)await completion.first().click();
  }
  await page.waitForFunction(count=>new Set([...document.querySelectorAll('a[href^="https://example.invalid/service/"]')].map(item=>item.href)).size===count,expected.link_count,{timeout:10000});
  const links=await page.locator('a[href^="https://example.invalid/service/"]').evaluateAll(items=>Array.from(new Set(items.map(item=>item.href))).sort());
  assert.deepEqual(links,[...expected.hrefs].sort(),'SERVICE_LINKS_CHANGED');results.service_links=links.length;
  for(const name of expected.service_names)assert(await page.locator('li[data-name]').filter({has:page.locator('.service-name',{hasText:name})}).count()||await page.getByText(name,{exact:true}).count(),'SERVICE_NAME_MISSING');
  const body=await page.locator('body').textContent();
  results.visible_container_rows=expected.container_names.filter(name=>body.includes(name)).length;
  assert.equal(results.visible_container_rows,5,'CONTAINER_TABLE_NOT_FIVE_ROWS');
  assert(!body.includes('fixture-worker-6')&&!body.includes('fixture-worker-7'),'CONTAINER_TABLE_LIMIT_CHANGED');
  const brand=await page.locator('li[data-name="AIOStreams"] .service-icon').first().evaluate(element=>{const style=getComputedStyle(element);return {image:style.backgroundImage.startsWith('url("data:image/'),mask:style.maskImage,webkitMask:style.webkitMaskImage,backgroundSize:style.backgroundSize};});
  assert(brand.image,'BRAND_LOGO_MISSING');assert.equal(brand.mask,'none','BRAND_LOGO_MASKED');
  for(const viewport of [{width:1280,height:1000},{width:1600,height:1000},{width:2560,height:1440},{width:390,height:844}]){
   await page.setViewportSize(viewport);await page.waitForTimeout(600);
   const shape=await page.evaluate(()=>{const wrapper=document.querySelector('#inner_wrapper > .container');const search=document.querySelector('.information-widget-search');const background=document.getElementById('background');const next=document.getElementById('__next');const inner=document.getElementById('inner_wrapper');const box=e=>{const r=e.getBoundingClientRect();return {x:r.x,width:r.width,height:r.height}};return {wrapper:wrapper?box(wrapper):null,search:search?box(search):null,background:box(background),nextBackground:getComputedStyle(next).backgroundColor,documentWidth:document.documentElement.scrollWidth,innerWidth:inner.clientWidth,innerScrollWidth:inner.scrollWidth,viewportWidth:window.innerWidth};});
   assert(shape.wrapper&&shape.search,'LAYOUT_SELECTORS_MISSING');assert(shape.wrapper.width<=1562,'CONTENT_TOO_WIDE');
   assert(shape.background.width>=viewport.width-1&&shape.background.height>=viewport.height-1,'BACKGROUND_NOT_FULL_VIEWPORT');
   assert(['rgba(0, 0, 0, 0)','transparent'].includes(shape.nextBackground),'OPAQUE_ROOT_HIDES_WALLPAPER');
   assert(shape.documentWidth<=viewport.width+2&&shape.innerScrollWidth<=shape.innerWidth+2,'HORIZONTAL_OVERFLOW');
   if(viewport.width>=1280)assert(Math.abs(shape.search.x+shape.search.width/2-(shape.wrapper.x+shape.wrapper.width/2))<=5,'SEARCH_NOT_CENTERED');
   await page.screenshot({path:path.join(output,'homepage-'+viewport.width+'.png'),fullPage:true});
   results.viewports.push({width:viewport.width,height:viewport.height,content_width:shape.wrapper.width,search_width:shape.search.width,background:'decoded-visible'});
  }
  results.status='PASS';fs.writeFileSync(path.join(output,'appearance-results.json'),JSON.stringify(results,null,2)+'\n');
  process.stdout.write('HOMEPAGE_APPEARANCE PASS viewports=4 service_links=23 container_rows=5\n');
 }catch(error){
  if(page)await page.screenshot({path:path.join(output,'appearance-failure.png'),fullPage:true}).catch(()=>{});
  results.status='FAIL';results.reason=String(error.message||'HOMEPAGE_APPEARANCE_FAILED').split('\n')[0].slice(0,180);fs.writeFileSync(path.join(output,'appearance-results.json'),JSON.stringify(results,null,2)+'\n');
  throw error;
 }finally{await browser.close();}
})().catch(error=>{process.stderr.write(String(error.message||'HOMEPAGE_APPEARANCE_FAILED').split('\n')[0]+'\n');process.exitCode=1;});
