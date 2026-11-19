// node test/blocker-live.mjs: every Shield list's sources answer with enough names (the internet's, not in npm test).
// Through a proxy: HTTPS_PROXY=http://127.0.0.1:1080 (Foxhole's), else directly.
import { LISTS, LIST_IDS, hashList } from "../dist/blocker.js";
import { download } from "../dist/global.js";

const proxy = process.env.HTTPS_PROXY ? new URL(process.env.HTTPS_PROXY) : undefined;
let bad = 0;
for (const id of LIST_IDS)
  for (const src of LISTS[id].from)
    for (const url of src.urls) {
      const t = Date.now();
      try {
        const body = await download(url, proxy && { host: proxy.hostname, port: Number(proxy.port) });
        const n = (await hashList(body.toString("utf8"))).length;
        const ok = n >= src.min;
        if (!ok && !src.optional) bad++;
        console.log(`${ok ? "ok  " : "FAIL"} ${id} ${n} names (${(body.length / 1e6).toFixed(1)} MB, ${Date.now() - t} ms) ${url}`);
      } catch (err) {
        if (!src.optional) bad++;
        console.log(`FAIL ${id} ${err.message} ${url}`);
      }
    }
process.exit(bad ? 1 : 0);
