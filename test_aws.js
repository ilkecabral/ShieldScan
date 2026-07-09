const puppeteer = require('puppeteer');
(async () => {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  page.on('console', msg => console.log('PAGE LOG:', msg.text()));
  page.on('pageerror', err => console.log('PAGE ERROR:', err.toString()));
  await page.goto('http://localhost:3000');
  
  try {
    await page.waitForSelector('.cib-amazon-aws', { timeout: 10000 });
    await page.evaluate(() => {
      const buttons = Array.from(document.querySelectorAll('button'));
      const btn = buttons.find(b => b.innerText && b.innerText.includes('Connect AWS Account'));
      if (btn) btn.click();
      else console.log("Button not found");
    });
    await new Promise(r => setTimeout(r, 2000));
  } catch (e) {
    console.log("Error:", e.message);
  }
  
  await browser.close();
})();
