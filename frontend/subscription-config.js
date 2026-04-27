/**
 * subscription-config.js
 * 订阅合约配置 + 链上读写工具
 * 以普通 <script> 加载（非 module），挂到 window 上。
 */
(function () {

  // ── 合约地址配置（按网络） ─────────────────────────────────────────────────
  var CONTRACTS = {
    testnet: {
      chainId:              97,
      chainName:            "BSC Testnet",
      rpcUrl:               "https://data-seed-prebsc-1-s1.binance.org:8545",
      subscriptionAddress:  "0x5C0B9ae96eBc735d18570084C4Dd75eE268D5a06",
      usdtAddress:          "0x5a526E46449021B5d666C4579fE043344905bC78",
      usdtDecimals:         6,
      explorerUrl:          "https://testnet.bscscan.com",
    },
    mainnet: {
      chainId:              56,
      chainName:            "BSC Mainnet",
      rpcUrl:               "https://bsc-dataseed.binance.org",
      subscriptionAddress:  "0xB9d76024723D4A25061B7336EBbBe1dA5243eCAF",
      usdtAddress:          "0x55d398326f99059fF775485246999027B3197955",
      usdtDecimals:         18,
      explorerUrl:          "https://bscscan.com",
    },
  };

  // localhost / 127.0.0.1 → testnet，其他域名 → mainnet
  var isProduction = !["localhost", "127.0.0.1"].includes(window.location.hostname);
  window.SUBSCRIPTION_CONFIG = isProduction ? CONTRACTS.mainnet : CONTRACTS.testnet;

  // ── ABI 编码工具（无需 ethers.js）────────────────────────────────────────
  function encodeAddress(addr) {
    return "000000000000000000000000" + addr.replace(/^0x/i, "").toLowerCase();
  }
  function encodeUint256(n) {
    return BigInt(n).toString(16).padStart(64, "0");
  }
  /** ABI-encode two strings (for identityKey(string,string) call) */
  function encodeStrings(s1, s2) {
    function encStr(s) {
      var bytes = [];
      for (var i = 0; i < s.length; i++) bytes.push(s.charCodeAt(i));
      var lenHex  = bytes.length.toString(16).padStart(64, "0");
      var dataHex = bytes.map(function(b) { return b.toString(16).padStart(2, "0"); }).join("");
      while (dataHex.length % 64 !== 0) dataHex += "00";
      return lenHex + dataHex;
    }
    var e1 = encStr(s1), e2 = encStr(s2);
    var off1 = (64).toString(16).padStart(64, "0");             // 0x40
    var off2 = (64 + e1.length / 2).toString(16).padStart(64, "0");
    return off1 + off2 + e1 + e2;
  }

  // ── 函数选择器（precomputed via keccak256）───────────────────────────────
  // keccak256("monthlyPrice()")              = 0xa06c5a24
  // keccak256("approve(address,uint256)")    = 0x095ea7b3
  // keccak256("subscribe(uint256)")          = 0x0f574ba7
  // keccak256("allowance(address,address)")  = 0xdd62ed3e
  // keccak256("identityKey(string,string)")  = 0x8582348f
  // keccak256("identityStatus(bytes32)")     = 0xa5ce8e58

  // ── eth_call helper ───────────────────────────────────────────────────────
  async function ethCall(rpcUrl, to, data) {
    var resp = await fetch(rpcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0", method: "eth_call",
        params: [{ to: to, data: data }, "latest"], id: 1,
      }),
    });
    var json = await resp.json();
    if (json.error) throw new Error(json.error.message);
    return json.result;
  }

  // ── localStorage 缓存 key ────────────────────────────────────────────────
  var CACHE_KEY_USDT     = "sub_price_usdt";
  var CACHE_KEY_RAW      = "sub_price_raw";
  var CACHE_KEY_DECIMALS = "sub_price_decimals";

  /** 从 localStorage 读取缓存价格（同步，无网络请求）*/
  window.getCachedMonthlyPrice = function () {
    var usdt     = parseFloat(localStorage.getItem(CACHE_KEY_USDT));
    var rawStr   = localStorage.getItem(CACHE_KEY_RAW);
    var decimals = parseInt(localStorage.getItem(CACHE_KEY_DECIMALS), 10);
    if (!usdt || !rawStr) return null;
    try {
      return { raw: BigInt(rawStr), usdt: usdt, decimals: decimals || 6 };
    } catch(e) { return null; }
  };

  /** 保存价格到 localStorage */
  function savePriceCache(raw, usdt, decimals) {
    localStorage.setItem(CACHE_KEY_USDT,     usdt.toString());
    localStorage.setItem(CACHE_KEY_RAW,      raw.toString());
    localStorage.setItem(CACHE_KEY_DECIMALS, decimals.toString());
  }

  // ── 读取 monthlyPrice（链上，并更新缓存）────────────────────────────────
  window.fetchSubscriptionMonthlyPrice = async function () {
    var cfg = window.SUBSCRIPTION_CONFIG;
    if (!cfg.subscriptionAddress) return null;
    try {
      var result = await ethCall(cfg.rpcUrl, cfg.subscriptionAddress, "0xa06c5a24");
      if (!result || result === "0x") return null;
      var raw     = BigInt(result);
      var divisor = BigInt(10) ** BigInt(cfg.usdtDecimals);
      var usdt    = Number(raw * 100n / divisor) / 100;
      // 更新缓存
      savePriceCache(raw, usdt, cfg.usdtDecimals);
      return { raw, usdt, decimals: cfg.usdtDecimals };
    } catch (e) {
      console.error("[Subscription] fetchMonthlyPrice:", e);
      // 链上失败时返回缓存
      return window.getCachedMonthlyPrice();
    }
  };

  // ── 折扣 localStorage 缓存 key ──────────────────────────────────────────
  var DISC_KEY_3M  = "sub_disc_3m";
  var DISC_KEY_6M  = "sub_disc_6m";
  var DISC_KEY_12M = "sub_disc_12m";

  /** 读取缓存的折扣基点（同步）。未缓存时返回合约默认值。 */
  function _getDiscounts() {
    return {
      d3m:  parseInt(localStorage.getItem(DISC_KEY_3M)  || "9500",  10),
      d6m:  parseInt(localStorage.getItem(DISC_KEY_6M)  || "9000",  10),
      d12m: parseInt(localStorage.getItem(DISC_KEY_12M) || "8500",  10),
    };
  }

  /**
   * 从链上读取 discount3M / discount6M / discount12M 并缓存到 localStorage。
   * selectors (precomputed via keccak256):
   *   discount3M()  = 0xdb3330bf
   *   discount6M()  = 0x52ef97ee
   *   discount12M() = 0xa56b9f8d
   */
  window.fetchSubscriptionDiscounts = async function () {
    var cfg = window.SUBSCRIPTION_CONFIG;
    if (!cfg.subscriptionAddress) return null;
    try {
      var [r3, r6, r12] = await Promise.all([
        ethCall(cfg.rpcUrl, cfg.subscriptionAddress, "0xdb3330bf"),
        ethCall(cfg.rpcUrl, cfg.subscriptionAddress, "0x52ef97ee"),
        ethCall(cfg.rpcUrl, cfg.subscriptionAddress, "0xa56b9f8d"),
      ]);
      var parse = function(hex) {
        return (hex && hex !== "0x") ? Number(BigInt(hex)) : null;
      };
      var d3m  = parse(r3);
      var d6m  = parse(r6);
      var d12m = parse(r12);
      if (d3m !== null && d6m !== null && d12m !== null) {
        localStorage.setItem(DISC_KEY_3M,  d3m.toString());
        localStorage.setItem(DISC_KEY_6M,  d6m.toString());
        localStorage.setItem(DISC_KEY_12M, d12m.toString());
        return { d3m, d6m, d12m };
      }
      return null;
    } catch (e) {
      console.error("[Subscription] fetchDiscounts:", e);
      return null;
    }
  };

  /**
   * 计算折扣后的总价（读 localStorage 缓存，与合约 quotePrice 逻辑一致）。
   * 折扣基点（bps）：10000 = 100%
   */
  window.calcSubscriptionPrice = function (usdt1Month, months) {
    var d = _getDiscounts();
    var bps;
    if      (months >= 12) bps = d.d12m;
    else if (months >= 6)  bps = d.d6m;
    else if (months >= 3)  bps = d.d3m;
    else                   bps = 10000;
    return (usdt1Month * months * bps / 10000).toFixed(2);
  };

  // ── 立即后台拉取价格缓存（不等 window.load，尽早填充缓存）────────────────
  // 不阻塞页面渲染；同时触发 "subscriptionPriceReady" 供各页面更新 UI
  // 页面加载时同时后台拉取价格和折扣
  (function _prefetch() {
    window.fetchSubscriptionMonthlyPrice().then(function (price) {
      if (price) {
        window.dispatchEvent(new CustomEvent("subscriptionPriceReady", { detail: price }));
      }
    });
    window.fetchSubscriptionDiscounts();  // 静默更新折扣缓存
  })();

  // ── 读取 USDT allowance ──────────────────────────────────────────────────
  window.fetchUsdtAllowance = async function (ownerAddr) {
    var cfg = window.SUBSCRIPTION_CONFIG;
    try {
      var data = "0xdd62ed3e" + encodeAddress(ownerAddr) + encodeAddress(cfg.subscriptionAddress);
      var result = await ethCall(cfg.rpcUrl, cfg.usdtAddress, data);
      return result && result !== "0x" ? BigInt(result) : 0n;
    } catch (e) {
      console.error("[Subscription] fetchAllowance:", e);
      return 0n;
    }
  };

  // ── 获取当前 wallet provider（兼容 Rabby / OKX / MetaMask 等）───────────
  function getProvider() {
    // 优先用登录时记录的 provider，fallback 到 window.ethereum
    var p = window._walletProvider || window.ethereum;
    if (!p) throw new Error("No wallet provider found. Please connect your wallet.");
    return p;
  }

  // ── 发送交易（eth_sendTransaction）───────────────────────────────────────
  async function sendTx(from, to, data) {
    var txHash = await getProvider().request({
      method: "eth_sendTransaction",
      params: [{ from: from, to: to, data: data }],
    });
    return txHash;
  }

  // ── 等待交易确认 ──────────────────────────────────────────────────────────
  async function waitForTx(txHash, maxWaitMs) {
    maxWaitMs = maxWaitMs || 120000;
    var cfg     = window.SUBSCRIPTION_CONFIG;
    var start   = Date.now();
    while (Date.now() - start < maxWaitMs) {
      await new Promise(function(r) { setTimeout(r, 3000); });
      try {
        var resp = await fetch(cfg.rpcUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            jsonrpc: "2.0", method: "eth_getTransactionReceipt",
            params: [txHash], id: 1,
          }),
        });
        var json = await resp.json();
        if (json.result && json.result.blockNumber) {
          if (json.result.status === "0x0") throw new Error("Transaction reverted.");
          return json.result;
        }
      } catch (e) {
        if (e.message === "Transaction reverted.") throw e;
      }
    }
    throw new Error("Transaction timeout.");
  }

  /**
   * 执行订阅支付：
   *   1. 检查 USDT allowance，不足则先 approve
   *   2. 调用 subscribe(months)
   *
   * @param {string}   walletAddr  用户钱包地址
   * @param {number}   months      订阅月数
   * @param {BigInt}   totalRaw    总金额（raw，含 decimals）
   * @param {Function} onStatus    状态回调 (message: string) => void
   * @returns {Promise<string>}    订阅 tx hash
   */
  window.executeSubscription = async function (walletAddr, months, totalRaw, onStatus) {
    var cfg = window.SUBSCRIPTION_CONFIG;

    // ── Step 0: 确保账户已授权 ────────────────────────────────────────────
    onStatus && onStatus("Connecting wallet…");
    var provider = getProvider();
    var accounts;
    try {
      accounts = await provider.request({ method: "eth_requestAccounts" });
    } catch (authErr) {
      if (authErr.code === 4100 || authErr.code === -32002) {
        accounts = await provider.request({ method: "eth_accounts" });
      } else {
        throw authErr;
      }
    }
    if (!accounts || accounts.length === 0) throw new Error("No wallet accounts found. Please reconnect your wallet.");
    // 始终用 provider 返回的当前账户作为 from，避免与传入的 walletAddr 不一致
    var fromAddr = accounts[0];

    // ── Step 1: 切换到正确链 ──────────────────────────────────────────────
    onStatus && onStatus("Checking network…");
    var chainHex = "0x" + cfg.chainId.toString(16);
    try {
      await provider.request({
        method: "wallet_switchEthereumChain",
        params: [{ chainId: chainHex }],
      });
    } catch (switchErr) {
      if (switchErr.code === 4902) {
        await provider.request({
          method: "wallet_addEthereumChain",
          params: [{
            chainId:          chainHex,
            chainName:        cfg.chainName,
            nativeCurrency:   { name: "BNB", symbol: "BNB", decimals: 18 },
            rpcUrls:          [cfg.rpcUrl],
            blockExplorerUrls: [cfg.explorerUrl],
          }],
        });
      } else {
        throw switchErr;
      }
    }

    // ── Step 2: USDT approve（如果 allowance 不足）────────────────────────
    onStatus && onStatus("Checking USDT allowance…");
    var allowance = await window.fetchUsdtAllowance(fromAddr);
    if (allowance < totalRaw) {
      onStatus && onStatus("Approving USDT… (confirm in wallet)");
      var approveData = "0x095ea7b3"
        + encodeAddress(cfg.subscriptionAddress)
        + encodeUint256(totalRaw);
      var approveTx = await sendTx(fromAddr, cfg.usdtAddress, approveData);
      onStatus && onStatus("Waiting for approve tx…");
      await waitForTx(approveTx);
    }

    // ── Step 3: subscribe(months) ─────────────────────────────────────────
    onStatus && onStatus("Subscribing… (confirm in wallet)");
    var subscribeData = "0x0f574ba7" + encodeUint256(months);
    var subscribeTx = await sendTx(fromAddr, cfg.subscriptionAddress, subscribeData);
    onStatus && onStatus("Waiting for subscription tx…");
    await waitForTx(subscribeTx);

    onStatus && onStatus("Success!");
    return subscribeTx;
  };

  /**
   * Gmail / GitHub 用户订阅支付。
   * Pro 归属绑定到身份哈希（不是付款钱包），任何钱包都可以代付。
   *
   * 流程：
   *   1. 连接钱包（仅用于付款）
   *   2. 调合约 identityKey(provider, id) 取得身份哈希
   *   3. 切换到正确链
   *   4. USDT approve（如不足）
   *   5. subscribeForIdentity(identity, months)
   *      selector: keccak256("subscribeForIdentity(bytes32,uint256)") = 0x6bffa9ca
   *
   * @param {string}   provider   "google" | "github"
   * @param {string}   id         Gmail 邮箱 或 GitHub login name
   * @param {number}   months     订阅月数
   * @param {BigInt}   totalRaw   总金额（raw，含 decimals）
   * @param {Function} onStatus   状态回调
   * @returns {Promise<string>}   订阅 tx hash
   */
  window.executeSubscriptionForIdentity = async function (provider, id, months, totalRaw, onStatus) {
    var cfg = window.SUBSCRIPTION_CONFIG;

    // ── Step 0: 使用已连接的 payment wallet ──────────────────────────────
    onStatus && onStatus("Preparing payment wallet…");
    var p = window._paymentWalletProvider || window._walletProvider || window.ethereum;
    if (!p) throw new Error("No wallet connected. Please connect a wallet first.");

    var accounts;
    try {
      accounts = await p.request({ method: "eth_requestAccounts" });
    } catch (authErr) {
      if (authErr.code === 4100 || authErr.code === -32002) {
        accounts = await p.request({ method: "eth_accounts" });
      } else {
        throw authErr;
      }
    }
    if (!accounts || accounts.length === 0) throw new Error("No wallet accounts found. Please unlock your wallet.");
    var payerAddress = accounts[0];
    onStatus && onStatus("Paying from: " + payerAddress.slice(0, 6) + "…" + payerAddress.slice(-4));

    // ── Step 1: 取得身份哈希 ──────────────────────────────────────────────
    onStatus && onStatus("Computing identity key…");
    var keyData   = "0x8582348f" + encodeStrings(provider, id);
    var hashRes   = await ethCall(cfg.rpcUrl, cfg.subscriptionAddress, keyData);
    if (!hashRes || hashRes === "0x" || hashRes.length < 66)
      throw new Error("Failed to get identity key from contract.");
    var identityHash = hashRes.slice(0, 66); // 0x + 64 hex chars = bytes32

    // ── Step 2: 切换到正确链 ──────────────────────────────────────────────
    onStatus && onStatus("Checking network…");
    var chainHex = "0x" + cfg.chainId.toString(16);
    try {
      await p.request({ method: "wallet_switchEthereumChain", params: [{ chainId: chainHex }] });
    } catch (switchErr) {
      if (switchErr.code === 4902) {
        await p.request({
          method: "wallet_addEthereumChain",
          params: [{
            chainId: chainHex, chainName: cfg.chainName,
            nativeCurrency: { name: "BNB", symbol: "BNB", decimals: 18 },
            rpcUrls: [cfg.rpcUrl], blockExplorerUrls: [cfg.explorerUrl],
          }],
        });
      } else throw switchErr;
    }

    // ── Step 3: USDT approve（如不足）────────────────────────────────────
    onStatus && onStatus("Checking USDT allowance…");
    var allowed = await window.fetchUsdtAllowance(payerAddress);
    if (allowed < totalRaw) {
      onStatus && onStatus("Approving USDT… (confirm in wallet)");
      var approveData = "0x095ea7b3"
        + encodeAddress(cfg.subscriptionAddress)
        + encodeUint256(totalRaw);
      var approveTx = await p.request({
        method: "eth_sendTransaction",
        params: [{ from: payerAddress, to: cfg.usdtAddress, data: approveData }],
      });
      onStatus && onStatus("Waiting for approve tx…");
      await waitForTx(approveTx);
    }

    // ── Step 4: subscribeForIdentity(identity, months) ────────────────────
    onStatus && onStatus("Subscribing… (confirm in wallet)");
    var subData = "0x6bffa9ca"
      + identityHash.slice(2)          // bytes32 identity (no 0x)
      + encodeUint256(months);         // uint256 months
    var subscribeTx = await p.request({
      method: "eth_sendTransaction",
      params: [{ from: payerAddress, to: cfg.subscriptionAddress, data: subData }],
    });
    onStatus && onStatus("Waiting for subscription tx…");
    await waitForTx(subscribeTx);

    onStatus && onStatus("Success!");
    return subscribeTx;
  };

  // ── Plan 状态缓存 key ─────────────────────────────────────────────────────
  var PLAN_KEY       = "sub_plan";           // "free" | "pro"
  var PLAN_EXPIRY_KEY = "sub_plan_expires_ts"; // unix seconds, "" = no expiry / free

  /** 读取缓存的 plan 状态（同步） */
  window.getCachedPlan = function () {
    var plan      = localStorage.getItem(PLAN_KEY) || "free";
    var expiryStr = localStorage.getItem(PLAN_EXPIRY_KEY) || "";
    var expiryTs  = expiryStr ? parseInt(expiryStr, 10) : 0;
    // 如果是 pro 但已过期，视为 free
    if (plan === "pro" && expiryTs > 0 && expiryTs < Math.floor(Date.now() / 1000)) {
      plan = "free";
    }
    return {
      plan:      plan,
      expiryTs:  expiryTs,                             // unix seconds
      isPro:     plan === "pro" && (expiryTs === 0 || expiryTs > Math.floor(Date.now() / 1000)),
    };
  };

  /** 保存 plan 状态到 localStorage */
  function savePlanCache(plan, expiryTs) {
    localStorage.setItem(PLAN_KEY,        plan);
    localStorage.setItem(PLAN_EXPIRY_KEY, expiryTs ? expiryTs.toString() : "");
  }

  /**
   * 从链上查询钱包的 Pro 状态，并更新 localStorage。
   * selector: keccak256("walletStatus(address)") = 0x4d6d0af8
   * returns (bool active, uint256 remainingSeconds)
   *
   * @param {string} walletAddr
   * @returns {Promise<{isPro: boolean, expiryTs: number}>}
   */
  window.fetchPlanFromChain = async function (walletAddr) {
    var cfg = window.SUBSCRIPTION_CONFIG;
    if (!cfg.subscriptionAddress || !walletAddr) return null;
    try {
      var data   = "0x4d6d0af8" + encodeAddress(walletAddr);
      var result = await ethCall(cfg.rpcUrl, cfg.subscriptionAddress, data);
      if (!result || result === "0x") return null;

      // Decode (bool active, uint256 remainingSeconds)
      // First 32 bytes: bool (0 or 1)
      // Next  32 bytes: uint256 remainingSeconds
      var active    = BigInt("0x" + result.slice(2, 66)) === 1n;
      var remaining = BigInt("0x" + result.slice(66, 130)); // seconds

      var expiryTs = active && remaining > 0n
        ? Math.floor(Date.now() / 1000) + Number(remaining)
        : 0;

      var plan = active ? "pro" : "free";
      savePlanCache(plan, expiryTs);

      window.dispatchEvent(new CustomEvent("planStatusReady", {
        detail: { isPro: active, expiryTs: expiryTs, plan: plan }
      }));

      return { isPro: active, expiryTs: expiryTs, plan: plan };
    } catch (e) {
      console.error("[Subscription] fetchPlanFromChain:", e);
      return null;
    }
  };

  /** 清除 plan 缓存（登出时调用）*/
  window.clearPlanCache = function () {
    localStorage.removeItem(PLAN_KEY);
    localStorage.removeItem(PLAN_EXPIRY_KEY);
  };

  /**
   * 从链上查询 Google / GitHub 用户的 Pro 状态（通过 identityStatus）。
   * 两步：先调 identityKey(provider, id) 拿到 bytes32，再调 identityStatus(hash)。
   *
   * @param {string} provider  "google" 或 "github"
   * @param {string} id        Google: email，GitHub: login name
   * @returns {Promise<{isPro: boolean, expiryTs: number, plan: string} | null>}
   */
  window.fetchPlanFromChainIdentity = async function (provider, id) {
    var cfg = window.SUBSCRIPTION_CONFIG;
    if (!cfg.subscriptionAddress || !provider || !id) return null;
    try {
      // Step 1: identityKey(provider, id) → bytes32 hash
      var keyData = "0x8582348f" + encodeStrings(provider, id);
      var hashResult = await ethCall(cfg.rpcUrl, cfg.subscriptionAddress, keyData);
      if (!hashResult || hashResult === "0x" || hashResult.length < 66) return null;
      var identityHash = hashResult.slice(0, 66); // 0x + 64 hex = bytes32

      // Step 2: identityStatus(hash) → (bool active, uint256 remainingSeconds)
      var statusData = "0xa5ce8e58" + identityHash.slice(2); // strip 0x
      var statusResult = await ethCall(cfg.rpcUrl, cfg.subscriptionAddress, statusData);
      if (!statusResult || statusResult === "0x" || statusResult.length < 130) return null;

      var active    = BigInt("0x" + statusResult.slice(2, 66)) === 1n;
      var remaining = BigInt("0x" + statusResult.slice(66, 130));
      var expiryTs  = active && remaining > 0n
        ? Math.floor(Date.now() / 1000) + Number(remaining)
        : 0;
      var plan = active ? "pro" : "free";

      savePlanCache(plan, expiryTs);
      window.dispatchEvent(new CustomEvent("planStatusReady", {
        detail: { isPro: active, expiryTs: expiryTs, plan: plan }
      }));
      return { isPro: active, expiryTs: expiryTs, plan: plan };
    } catch (e) {
      console.error("[Subscription] fetchPlanFromChainIdentity:", e);
      return null;
    }
  };

})();
