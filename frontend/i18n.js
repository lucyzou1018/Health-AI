(function () {
  var STORAGE_KEY = 'codeautrix_lang';
  var lang = localStorage.getItem(STORAGE_KEY) || 'en';
  var path = (location.pathname.split('/').pop() || 'index.html').toLowerCase();
  if (path === '' || path === '/') path = 'index.html';

  function setText(selector, value) {
    var node = document.querySelector(selector);
    if (node) node.textContent = value;
  }

  function setHTML(selector, value) {
    var node = document.querySelector(selector);
    if (node) node.innerHTML = value;
  }

  function setAll(selector, values) {
    var nodes = document.querySelectorAll(selector);
    nodes.forEach(function (node, index) {
      if (typeof values[index] !== 'undefined') node.textContent = values[index];
    });
  }

  function applyCommon(copy) {
    document.documentElement.lang = copy.htmlLang;
    document.title = copy.title;
    setAll('.lp-nav-links .lp-nav-item', copy.navItems);
    setText('.lp-nav-cta', copy.getStarted);
    setText('[data-lang-label]', copy.langLabel);
  }

  function applyIndex(copy) {
    applyCommon(copy);
    setText('.hero-badge', copy.heroBadge);
    setText('.hero-subtitle', copy.heroSubtitle);
    setText('.hero-desc', copy.heroDesc);
    setText('.hero-buttons .hero-btn--primary .btn-text', copy.heroPrimary);
    setText('.hero-buttons .hero-btn--ghost span', copy.heroGhost);
    setAll('.hero-trust .trust-item', copy.trustItems);
    setAll('.stat-label', copy.statLabels);
    setAll('#features .section-header .section-eyebrow, #how-it-works .section-header .section-eyebrow, .lp-tech-section .section-header .section-eyebrow, #faq .section-header .section-eyebrow', copy.sectionEyebrows);
    setAll('#features .section-title, #how-it-works .section-title, .lp-tech-section .section-title, #faq .section-title', copy.sectionTitles);
    setAll('#features .section-desc, #how-it-works .section-desc, #faq .section-desc', copy.sectionDescs);
    setAll('.feature-title', copy.featureTitles);
    setAll('.feature-desc', copy.featureDescs);
    setAll('.feature-tag', [copy.featureTag]);
    setAll('.feature-cta', copy.featureCtas);
    setAll('.feature-list', []);
    document.querySelectorAll('.feature-list').forEach(function (list, index) {
      var items = copy.featureLists[index];
      if (!items) return;
      var li = list.querySelectorAll('li');
      li.forEach(function (node, itemIndex) {
        if (typeof items[itemIndex] !== 'undefined') node.textContent = items[itemIndex];
      });
    });
    setAll('.step-title', copy.stepTitles);
    setAll('.step-desc', copy.stepDescs);
    setAll('.tech-name', copy.techNames);
    setAll('.tech-desc', copy.techDescs);
    document.querySelectorAll('.faq-item').forEach(function (item, index) {
      var q = item.querySelector('.faq-q span');
      var a = item.querySelector('.faq-a p');
      if (q && copy.faqQuestions[index]) q.innerHTML = copy.faqQuestions[index];
      if (a && copy.faqAnswers[index]) a.innerHTML = copy.faqAnswers[index];
    });
    setText('.cta-title', copy.ctaTitle);
    setText('.cta-desc', copy.ctaDesc);
    setText('.cta-btn span:first-child', copy.ctaButton);
    setText('.footer-tagline', copy.footerTagline);
    setAll('.footer-links a', copy.footerLinks);
  }

  function applyPricing(copy) {
    applyCommon(copy);
    setText('.pricing-eyebrow', copy.heroEyebrow);
    setText('.pricing-title', copy.heroTitle);
    setHTML('.pricing-subtitle', copy.heroSubtitle);
    setAll('.pricing-status__pill', copy.heroPills);
    setText('.pricing-highlight__label', copy.highlightLabel);
    setText('.pricing-highlight__metric', copy.highlightMetric);
    setText('.pricing-highlight__text', copy.highlightText);
    setAll('.pricing-mini-stat__k', copy.miniStatKeys);
    setAll('.pricing-mini-stat__v', copy.miniStatValues);
    setAll('.pricing-section-head .section-eyebrow', copy.sectionEyebrows);
    setAll('.pricing-section-head .section-title', copy.sectionTitles);
    setAll('.pricing-section-head .section-desc', copy.sectionDescs);
    setAll('.plan-name', copy.planNames);
    setAll('.plan-desc', copy.planDescs);
    setAll('.plan-price__sub', copy.planPriceSubs);
    setAll('.plan-meta', copy.planMetas);
    setAll('.plan-cta', copy.planCtas);
    setAll('.plan-badge', [copy.planBadge]);
    document.querySelectorAll('.plan-features').forEach(function (list, index) {
      var items = copy.planFeatures[index];
      var li = list.querySelectorAll('li');
      li.forEach(function (node, itemIndex) {
        if (typeof items[itemIndex] !== 'undefined') node.textContent = items[itemIndex];
      });
    });
    setAll('.compare-table thead th', copy.compareHeads);
    document.querySelectorAll('.compare-table tbody tr').forEach(function (row, index) {
      var values = copy.compareRows[index];
      if (!values) return;
      row.querySelectorAll('td').forEach(function (cell, cellIndex) {
        if (typeof values[cellIndex] !== 'undefined') cell.textContent = values[cellIndex];
      });
    });
    document.querySelectorAll('.pricing-faq-card').forEach(function (card, index) {
      var h = card.querySelector('h3');
      var p = card.querySelector('p');
      if (h && copy.faqTitles[index]) h.textContent = copy.faqTitles[index];
      if (p && copy.faqTexts[index]) p.textContent = copy.faqTexts[index];
    });
    setText('.pricing-cta-card .pricing-eyebrow', copy.ctaEyebrow);
    setText('.pricing-cta-card h2', copy.ctaTitle);
    setText('.pricing-cta-card p', copy.ctaText);
    setText('.pricing-cta-actions .hero-btn--primary .btn-text', copy.ctaPrimary);
    setText('.pricing-cta-actions .hero-btn--ghost', copy.ctaSecondary);
  }

  var translations = {
    en: {
      common: {
        htmlLang: 'en',
        title: path === 'pricing.html' ? 'Pricing — CodeAutrix' : (path === 'workspace.html' ? 'CodeAutrix Console' : 'CodeAutrix — Intelligent Skill Security Platform'),
        navItems: ['Features', 'How It Works', 'FAQ', 'Pricing', 'Dashboard'],
        getStarted: 'Get Started →',
        langLabel: 'English'
      },
      index: {
        heroBadge: 'Smart Risk Control · Audit · Stress Test · Full-Stack Protection',
        heroSubtitle: 'Comprehensive Security for Your Skills & Contracts',
        heroDesc: 'Upload code and get instant results — automated permission audits, vulnerability detection, and stress testing to keep every line of code production-ready.',
        heroPrimary: 'Get Started',
        heroGhost: 'Learn More',
        trustItems: ['Real-time Detection', 'Multi-chain Support', 'AI-Powered'],
        statLabels: ['Audit Growth Rate', 'Vulnerability Detection Rate', 'Average Scan Time', 'Supported Chain Types'],
        sectionEyebrows: ['Core Features', 'How It Works', 'Technology', 'FAQ'],
        sectionTitles: ['All-in-One Security Detection Platform', 'Three Steps to Complete Security', 'Enterprise-Grade Security Detection Engine', 'Frequently Asked Questions'],
        sectionDescs: ['Full-lifecycle security coverage for Skills — making security a natural part of every development workflow.', 'From code upload to report generation — fully automated, zero manual configuration.', 'Everything you need to know about CodeAutrix — clear answers, no fluff.'],
        featureTag: 'Most Popular',
        featureTitles: ['Skill Security Audit', 'Contract Vulnerability Scan', 'Stress Test', 'Professional Report Export'],
        featureDescs: [
          'One-click comprehensive scan for Skill security risks — intelligently detects permission vulnerabilities, configuration issues, and injection threats with a multi-dimensional health score.',
          'Precise scanning of EVM / Solana contract source code — detects reentrancy attacks, integer overflows, access control issues, and other high-severity vulnerabilities.',
          'Simulate real high-concurrency scenarios, collect P50/P95/P99 latency and throughput metrics, and fully evaluate system capacity limits.',
          'Automatically generates structured HTML reports covering risk summaries, detailed vulnerability lists, and remediation suggestions — ready to share with your team or clients.'
        ],
        featureLists: [
          ['Smart permission boundary analysis', 'API call chain security tracing', 'Sensitive data leakage detection', 'Composite security score (0–100)'],
          ['Reentrancy attack detection', 'Integer overflow / underflow analysis', 'Access control vulnerabilities', 'Gas optimization suggestions'],
          ['Configurable concurrency & run count', 'Real-time performance metrics', 'Latency percentile analysis', 'Success rate & error attribution']
        ],
        featureCtas: ['Audit Now →', 'Scan Now →', 'Run Test →'],
        stepTitles: ['Upload Code', 'AI Analysis', 'Get Your Report'],
        stepDescs: [
          'Drag and drop your Skill zip or contract source files. Supports multiple formats with instant parsing.',
          'Large models deeply parse code logic and combine with rule libraries to identify security risks — covering OWASP TOP 10 and on-chain-specific vulnerabilities.',
          'Professional report generated in seconds — includes risk ratings, vulnerability details, and remediation guidance. One-click download.'
        ],
        techNames: ['Static Analysis', 'AI Reasoning', 'Live Execution', 'Multi-chain', 'Quantified Scoring', 'Rule Library'],
        techDescs: [
          'AST-level code parsing for precise risk localization',
          'LLMs understand code semantics to uncover hidden logic flaws',
          'Dynamic stress-test engine simulating real production load',
          'EVM-compatible chains + Solana, with more on the way',
          'CVSS-based risk scoring for objective security measurement',
          'Continuously updated rules covering the latest attack vectors'
        ],
        faqQuestions: [
          'What file formats does CodeAutrix support for upload?',
          'Is my uploaded code stored or shared after scanning?',
          'Do I need to register or connect a wallet to use CodeAutrix?',
          'Is there a daily task limit?',
          'How is the security score calculated?',
          'Which blockchains does Contract Audit support?',
          'Can I export the scan report?',
          'What is the difference between Skill Audit and Contract Audit?'
        ],
        faqAnswers: [
          'Skill Security Audit accepts <strong>.zip</strong> archives containing your Skill or Agent code. Contract Audit supports <strong>.sol</strong> Solidity source files (EVM chains) and <strong>Rust-based</strong> Solana programs, as well as on-chain contract addresses for live analysis. All uploads are processed server-side and never shared with third parties.',
          'Your code is stored only for the duration of the scan task and its associated report. It is never shared with other users or used for training. You can delete any task and its artifacts at any time from the Workspace panel.',
          'No registration is required to run scans. Connecting a wallet (MetaMask or WalletConnect) is optional — it links your session to a persistent identity so your scan history is preserved across devices. Without a wallet, your tasks are tied to your browser session only.',
          'Yes. Each IP address may submit up to <strong>3 scan tasks per UTC calendar day</strong> across all scan types combined (Skill Audit, Contract Audit, and Stress Test). The counter resets at midnight UTC. This limit ensures fair usage and service stability for all users.',
          'The Skill Security Audit produces five independent dimension scores — <strong>Privacy, Privilege, Integrity, Supply Chain, and Stability</strong> — each rated 0–100. The overall score is their arithmetic mean. Scores ≥ 80 are considered healthy; scores below 60 indicate significant risk. Each dimension deducts points based on matched risk patterns weighted by severity.',
          'Contract Audit supports all <strong>EVM-compatible chains</strong> (Ethereum, BNB Chain, Polygon, Arbitrum, Base, etc.) via Solidity source code or on-chain address, and <strong>Solana</strong> programs via Rust/Anchor source code. More chains will be added in future releases.',
          'Yes. Every completed scan generates a structured report viewable in the browser. For Skill Security Audit, a professional <strong>PDF report</strong> can be downloaded directly from the report page — suitable for sharing with your team, clients, or auditors.',
          '<strong>Skill Security Audit</strong> targets Skill and Agent packages (AI tool code). It checks permissions, privilege escalation, data leakage, obfuscation, supply chain risks, and more, producing a multi-dimension health score.<br><br><strong>Contract Audit</strong> targets smart contracts — both EVM (Solidity) and Solana (Rust/Anchor). It detects reentrancy, integer overflow, access control flaws, gas inefficiencies, and other chain-specific vulnerabilities using AI-powered analysis.'
        ],
        ctaTitle: 'Ready to Secure Your Skills?',
        ctaDesc: 'Free to start, no registration required — upload your code and get a security report instantly.',
        ctaButton: 'Start Scanning Now',
        footerTagline: 'Intelligent Skill Security Platform',
        footerLinks: ['Features', 'How It Works', 'FAQ', 'Launch App']
      },
      pricing: {
        heroEyebrow: 'Pricing Preview',
        heroTitle: 'Simple usage today. Unlimited workflows tomorrow.',
        heroSubtitle: 'CodeAutrix currently offers <strong>3 free scans per day</strong> across code health checks, contract scans, and upload stress tests. Paid plans are a static preview for upcoming billing, designed to unlock unlimited usage and team workflows once payments go live.',
        heroPills: ['Current: Free tier only', 'Future: Paid plans unlock unlimited usage'],
        highlightLabel: 'Free Tier',
        highlightMetric: '3 Free Scans / Day',
        highlightText: 'The free quota is shared across Skill health checks, contract audits, and stress tests. It resets daily and is intended for evaluation and light usage.',
        miniStatKeys: ['Skill Audit', 'Contract Scan', 'Stress Test', 'Billing'],
        miniStatValues: ['Included', 'Included', 'Included', 'Coming soon'],
        sectionEyebrows: ['Plans', 'Comparison', 'FAQ'],
        sectionTitles: ['Choose the scale you need', 'What changes when billing arrives', 'Short answers before payment launches'],
        sectionDescs: ['All paid tiers below are preview-only at this stage. The direction is clear: free for exploration, paid for unlimited production usage.'],
        planBadge: 'Recommended',
        planNames: ['Free', 'Pro', 'Enterprise'],
        planDescs: ['Best for trying the platform and validating workflows.', 'For builders who need unlimited scans and faster iteration.', 'For teams that want scale, governance, and private delivery.'],
        planPriceSubs: ['available now', '/ month, coming soon', 'contact plan, coming soon'],
        planMetas: ['Current live plan', 'Future paid tier', 'Designed for organization rollout'],
        planFeatures: [
          ['3 scans per day total', 'Code health checks for uploaded repos or files', 'Smart contract security scans', 'Basic stress testing for uploaded code', 'Browser-based reports'],
          ['Unlimited code health checks', 'Unlimited contract scans', 'Unlimited stress test runs', 'Priority queue and faster processing', 'Expanded export and report history'],
          ['Unlimited organization-wide usage', 'Team access and shared reporting', 'Private deployment and custom limits', 'Dedicated support and onboarding', 'Custom integration pathways']
        ],
        planCtas: ['Start Free', 'Coming Soon', 'Talk to Us'],
        compareHeads: ['Capability', 'Free', 'Pro', 'Enterprise'],
        compareRows: [
          ['Daily task limit', '3 total', 'Unlimited', 'Unlimited'],
          ['Code health checks', 'Included', 'Unlimited', 'Unlimited'],
          ['Contract vulnerability scans', 'Included', 'Unlimited', 'Unlimited'],
          ['Stress test execution', 'Included', 'Unlimited', 'Unlimited'],
          ['Report retention', 'Basic', 'Extended', 'Custom policy'],
          ['Team collaboration', 'Not included', 'Lightweight', 'Advanced'],
          ['Support level', 'Community style', 'Priority', 'Dedicated']
        ],
        faqTitles: ['Can I pay now?', 'What is limited today?', 'What will paid plans unlock?', 'Will pricing stay exactly the same?'],
        faqTexts: [
          'No. The platform currently runs on the free tier only.',
          'You can run up to three total tasks per day, shared across code health checks, contract scans, and stress tests.',
          'The core promise is unlimited usage, with higher tiers adding faster processing, longer retention, and team-oriented controls.',
          'Not necessarily. This page is a forward-looking placeholder, so plan names and prices may change when payment support is released.'
        ],
        ctaEyebrow: 'Start now',
        ctaTitle: 'Use the free tier today and grow into unlimited later.',
        ctaText: 'Run your first code health check, contract scan, or stress test from the dashboard.',
        ctaPrimary: 'Start Scanning Now',
        ctaSecondary: ''
      }
    },
    'zh-CN': {
      common: {
        htmlLang: 'zh-CN',
        title: path === 'pricing.html' ? '定价方案 — CodeAutrix' : (path === 'workspace.html' ? 'CodeAutrix 控制台' : 'CodeAutrix — 智能代码安全检测平台'),
        navItems: ['功能', '使用方式', '常见问题', '定价', '控制台'],
        getStarted: '立即开始 →',
        langLabel: '简体中文'
      },
      index: {
        heroBadge: '智能风控 · 安全审计 · 压力测试 · 全栈防护',
        heroSubtitle: '面向技能与合约的全链路代码健康检查',
        heroDesc: '上传代码即可获得即时结果，自动完成权限审计、漏洞检测与压力测试，让每一行代码都更接近生产可用状态。',
        heroPrimary: '立即开始',
        heroGhost: '了解更多',
        trustItems: ['实时检测', '多链支持', 'AI 驱动'],
        statLabels: ['审计增长率', '漏洞检出率', '平均扫描时间', '支持链类型'],
        sectionEyebrows: ['核心能力', '使用方式', '技术体系', '常见问题'],
        sectionTitles: ['一体化安全检测平台', '三步完成代码安全检查', '企业级安全检测引擎', '常见问题'],
        sectionDescs: ['围绕上传代码、技能包与合约的完整安全覆盖，让安全检测自然融入开发流程。', '从上传代码到生成报告，全流程自动化，无需手动配置。', '关于 CodeAutrix 的关键信息都在这里，直接、清晰、不绕弯。'],
        featureTag: '最受欢迎',
        featureTitles: ['Skill 安全审计', '合约漏洞扫描', '压力测试', '专业报告导出'],
        featureDescs: [
          '一键检测 Skill 安全风险，智能识别权限越界、配置风险、注入问题等威胁，并输出多维健康评分。',
          '针对 EVM / Solana 合约源码进行精准扫描，识别重入、整数溢出、访问控制缺陷等高危漏洞。',
          '模拟真实高并发场景，采集 P50 / P95 / P99 延迟与吞吐指标，全面评估系统容量上限。',
          '自动生成结构化 HTML 报告，覆盖风险摘要、漏洞明细与修复建议，方便团队协作和结果交付。'
        ],
        featureLists: [
          ['智能权限边界分析', 'API 调用链安全追踪', '敏感数据泄露检测', '综合安全评分（0–100）'],
          ['重入攻击检测', '整数溢出 / 下溢分析', '访问控制漏洞识别', 'Gas 优化建议'],
          ['并发数与运行次数可配置', '实时性能指标采集', '延迟分位分析', '成功率与错误归因']
        ],
        featureCtas: ['立即审计 →', '立即扫描 →', '开始测试 →'],
        stepTitles: ['上传代码', 'AI 深度分析', '获取报告'],
        stepDescs: [
          '拖拽上传 Skill 压缩包或合约源码文件，支持多种格式并可即时解析。',
          '大模型结合规则库深入理解代码逻辑，定位安全风险，覆盖 OWASP TOP 10 与链上特定漏洞。',
          '数秒内生成专业报告，包含风险评级、漏洞细节与修复建议，并支持一键下载。'
        ],
        techNames: ['静态分析', 'AI 推理', '实时执行', '多链支持', '量化评分', '规则库'],
        techDescs: [
          '基于 AST 的代码解析，实现精确风险定位',
          '借助大模型理解代码语义，发现隐藏逻辑缺陷',
          '动态压力测试引擎模拟真实生产负载',
          '支持 EVM 系链与 Solana，并持续扩展',
          '基于 CVSS 的风险评分，更客观衡量安全水平',
          '持续更新的检测规则覆盖最新攻击向量'
        ],
        faqQuestions: [
          'CodeAutrix 支持上传哪些文件格式？',
          '上传后的代码会被存储或共享吗？',
          '使用 CodeAutrix 需要注册或连接钱包吗？',
          '每天有任务次数限制吗？',
          '安全评分是如何计算的？',
          'Contract Audit 目前支持哪些链？',
          '可以导出扫描报告吗？',
          'Skill Audit 和 Contract Audit 有什么区别？'
        ],
        faqAnswers: [
          'Skill Security Audit 支持上传包含 Skill 或 Agent 代码的 <strong>.zip</strong> 压缩包。Contract Audit 支持上传 <strong>.sol</strong> Solidity 源码（EVM 链）和基于 <strong>Rust</strong> 的 Solana 程序，也支持填写链上合约地址进行实时分析。所有上传内容均在服务端处理，不会向第三方共享。',
          '你的代码仅在扫描任务及其关联报告的生命周期内保留，不会与其他用户共享，也不会被用于训练。你可以在 Workspace 面板中随时删除任务及其产物。',
          '运行扫描不需要注册。连接钱包（MetaMask 或 WalletConnect）是可选的，它会把当前会话关联到一个持久身份上，以便跨设备保留扫描历史；不连接钱包时，任务仅绑定在当前浏览器会话中。',
          '有。每个 IP 地址在每个 UTC 自然日内最多可提交 <strong>3 次扫描任务</strong>，该配额在 Skill Audit、Contract Audit 与 Stress Test 之间共享，并会在 UTC 零点重置。',
          'Skill 安全审计会输出五个独立维度分数：<strong>隐私、权限、完整性、供应链、稳定性</strong>，每个维度为 0–100 分，总分为五项平均值。80 分以上表示健康，60 分以下表示风险较高。每个维度会根据匹配到的风险模式及严重程度进行扣分。',
          'Contract Audit 支持所有 <strong>EVM 兼容链</strong>（如 Ethereum、BNB Chain、Polygon、Arbitrum、Base 等），可通过 Solidity 源码或链上地址进行分析；同时支持 <strong>Solana</strong> 程序（Rust/Anchor 源码）。后续会持续扩展更多链。',
          '可以。每次完成扫描后都会生成结构化报告并可在浏览器中查看。针对 Skill Security Audit，还支持从报告页直接下载专业 <strong>PDF 报告</strong>，方便团队或客户共享。',
          '<strong>Skill Security Audit</strong> 面向 Skill 和 Agent 代码包（AI 工具代码），重点检测权限越界、提权、数据泄露、混淆、供应链风险等问题，并输出多维健康分数。<br><br><strong>Contract Audit</strong> 面向智能合约，同时支持 EVM（Solidity）和 Solana（Rust/Anchor），借助 AI 分析识别重入、整数溢出、访问控制缺陷、Gas 效率问题等链特定漏洞。'
        ],
        ctaTitle: '准备好给代码做一次健康检查了吗？',
        ctaDesc: '免费即可开始，无需注册，上传代码后即可立即获得安全报告。',
        ctaButton: '立即开始扫描',
        footerTagline: '智能代码安全检测平台',
        footerLinks: ['功能', '使用方式', '常见问题', '启动应用']
      },
      pricing: {
        heroEyebrow: '定价预览',
        heroTitle: '今天先免费试用，未来解锁无限使用。',
        heroSubtitle: 'CodeAutrix 当前提供 <strong>每天 3 次免费扫描</strong>，配额在代码健康检查、合约扫描与上传代码压力测试之间共享。付费方案目前是静态预览页，用于展示未来上线支付后将如何解锁无限量使用与团队能力。',
        heroPills: ['当前：仅开放免费版', '未来：付费后可无限使用'],
        highlightLabel: '免费版',
        highlightMetric: '每日 3 次免费扫描',
        highlightText: '免费配额在 Skill 健康检查、合约审计与压力测试之间共享，每日重置，适合体验与轻量使用。',
        miniStatKeys: ['Skill 审计', '合约扫描', '压力测试', '支付能力'],
        miniStatValues: ['已包含', '已包含', '已包含', '即将上线'],
        sectionEyebrows: ['方案', '对比', '常见问题'],
        sectionTitles: ['选择适合你的使用规模', '支付上线后会带来什么变化', '支付功能上线前的几个说明'],
        sectionDescs: ['下方所有付费档位目前都只是预览。整体方向很明确：免费用于体验，付费解锁无限量生产使用。'],
        planBadge: '推荐',
        planNames: ['免费版', '专业版', '企业版'],
        planDescs: ['适合快速体验平台与验证工作流。', '适合需要无限扫描与更快迭代的开发者。', '适合需要规模化治理、私有化与团队协作的组织。'],
        planPriceSubs: ['当前可用', '/ 月，即将上线', '联系定制，即将上线'],
        planMetas: ['当前已开放方案', '未来付费方案', '面向组织级落地'],
        planFeatures: [
          ['每天总共 3 次扫描', '支持上传代码健康检查', '支持智能合约安全扫描', '支持基础压力测试', '浏览器内查看报告'],
          ['代码健康检查无限量', '合约扫描无限量', '压力测试无限量', '优先队列与更快处理速度', '更长的报告历史与导出能力'],
          ['组织级无限量使用', '团队共享报告与协作能力', '私有化部署与自定义限制', '专属支持与上线协助', '可定制集成方案']
        ],
        planCtas: ['免费开始', '即将上线', '联系我们'],
        compareHeads: ['能力项', '免费版', '专业版', '企业版'],
        compareRows: [
          ['每日任务上限', '3 次', '无限量', '无限量'],
          ['代码健康检查', '已包含', '无限量', '无限量'],
          ['合约漏洞扫描', '已包含', '无限量', '无限量'],
          ['压力测试执行', '已包含', '无限量', '无限量'],
          ['报告保留时长', '基础', '扩展', '自定义策略'],
          ['团队协作', '不包含', '轻量支持', '高级支持'],
          ['支持级别', '社区式', '优先支持', '专属支持']
        ],
        faqTitles: ['现在可以付费吗？', '当前受限的是什么？', '未来付费后会解锁什么？', '这个价格以后会完全不变吗？'],
        faqTexts: [
          '还不可以。当前平台只开放免费模式。',
          '你目前每天最多可运行 3 个任务，这个配额在代码健康检查、合约扫描与压力测试之间共享。',
          '核心承诺是无限量使用，更高档位还会增加更快处理、更长保留周期和团队协作能力。',
          '不一定。这一页是面向未来支付功能的占位预览，正式上线时套餐名称和价格都可能调整。'
        ],
        ctaEyebrow: '现在开始',
        ctaTitle: '今天先用免费版，未来再升级到无限量。',
        ctaText: '现在就去 Dashboard 运行你的第一条代码健康检查、合约扫描或压力测试。',
        ctaPrimary: '立即开始扫描',
        ctaSecondary: ''
      }
    }
  };

  function applyLanguage(nextLang) {
    var copy = translations[nextLang] || translations.en;
    var pageCommon = copy.common;
    if (path === 'pricing.html') {
      pageCommon.title = copy.common.title;
      applyPricing({
        htmlLang: pageCommon.htmlLang,
        title: pageCommon.title,
        navItems: pageCommon.navItems,
        getStarted: pageCommon.getStarted,
        langLabel: pageCommon.langLabel,
        heroEyebrow: copy.pricing.heroEyebrow,
        heroTitle: copy.pricing.heroTitle,
        heroSubtitle: copy.pricing.heroSubtitle,
        heroPills: copy.pricing.heroPills,
        highlightLabel: copy.pricing.highlightLabel,
        highlightMetric: copy.pricing.highlightMetric,
        highlightText: copy.pricing.highlightText,
        miniStatKeys: copy.pricing.miniStatKeys,
        miniStatValues: copy.pricing.miniStatValues,
        sectionEyebrows: copy.pricing.sectionEyebrows,
        sectionTitles: copy.pricing.sectionTitles,
        sectionDescs: copy.pricing.sectionDescs,
        planBadge: copy.pricing.planBadge,
        planNames: copy.pricing.planNames,
        planDescs: copy.pricing.planDescs,
        planPriceSubs: copy.pricing.planPriceSubs,
        planMetas: copy.pricing.planMetas,
        planFeatures: copy.pricing.planFeatures,
        planCtas: copy.pricing.planCtas,
        compareHeads: copy.pricing.compareHeads,
        compareRows: copy.pricing.compareRows,
        faqTitles: copy.pricing.faqTitles,
        faqTexts: copy.pricing.faqTexts,
        ctaEyebrow: copy.pricing.ctaEyebrow,
        ctaTitle: copy.pricing.ctaTitle,
        ctaText: copy.pricing.ctaText,
        ctaPrimary: copy.pricing.ctaPrimary,
        ctaSecondary: copy.pricing.ctaSecondary
      });
    } else if (path === 'workspace.html') {
      applyCommon({
        htmlLang: pageCommon.htmlLang,
        title: pageCommon.title,
        navItems: pageCommon.navItems,
        getStarted: pageCommon.getStarted,
        langLabel: pageCommon.langLabel
      });
      if (typeof window.applyWorkspaceLocale === 'function') {
        window.applyWorkspaceLocale(nextLang);
      }
    } else {
      applyIndex({
        htmlLang: pageCommon.htmlLang,
        title: pageCommon.title,
        navItems: pageCommon.navItems,
        getStarted: pageCommon.getStarted,
        langLabel: pageCommon.langLabel,
        heroBadge: copy.index.heroBadge,
        heroSubtitle: copy.index.heroSubtitle,
        heroDesc: copy.index.heroDesc,
        heroPrimary: copy.index.heroPrimary,
        heroGhost: copy.index.heroGhost,
        trustItems: copy.index.trustItems,
        statLabels: copy.index.statLabels,
        sectionEyebrows: copy.index.sectionEyebrows,
        sectionTitles: copy.index.sectionTitles,
        sectionDescs: copy.index.sectionDescs,
        featureTag: copy.index.featureTag,
        featureTitles: copy.index.featureTitles,
        featureDescs: copy.index.featureDescs,
        featureLists: copy.index.featureLists,
        featureCtas: copy.index.featureCtas,
        stepTitles: copy.index.stepTitles,
        stepDescs: copy.index.stepDescs,
        techNames: copy.index.techNames,
        techDescs: copy.index.techDescs,
        faqQuestions: copy.index.faqQuestions,
        faqAnswers: copy.index.faqAnswers,
        ctaTitle: copy.index.ctaTitle,
        ctaDesc: copy.index.ctaDesc,
        ctaButton: copy.index.ctaButton,
        footerTagline: copy.index.footerTagline,
        footerLinks: copy.index.footerLinks
      });
    }

    document.querySelectorAll('[data-lang-switch]').forEach(function (switcher) {
      switcher.querySelectorAll('[data-lang-option]').forEach(function (option) {
        option.classList.toggle('is-active', option.getAttribute('data-lang-option') === nextLang);
      });
    });

    window.dispatchEvent(new CustomEvent("codeautrix:langchange", { detail: { lang: nextLang } }));
  }

  /* ── Close all nav dropdowns (both help and lang) ── */
  function closeAllDropdowns() {
    document.querySelectorAll('[data-lang-switch]').forEach(function (sw) {
      sw.classList.remove('is-open');
      var t = sw.querySelector('.lang-switch__trigger');
      var m = sw.querySelector('.lang-switch__menu');
      if (t) t.setAttribute('aria-expanded', 'false');
      if (m) m.setAttribute('aria-hidden', 'true');
    });
    document.querySelectorAll('[data-help-switch]').forEach(function (sw) {
      sw.classList.remove('is-open');
      var t = sw.querySelector('.help-switch__trigger');
      var m = sw.querySelector('.help-switch__menu');
      if (t) t.setAttribute('aria-expanded', 'false');
      if (m) m.setAttribute('aria-hidden', 'true');
    });
  }

  document.querySelectorAll('[data-lang-switch]').forEach(function (switcher) {
    var trigger = switcher.querySelector('.lang-switch__trigger');
    var menu = switcher.querySelector('.lang-switch__menu');
    var options = switcher.querySelectorAll('[data-lang-option]');

    function closeMenu() {
      switcher.classList.remove('is-open');
      trigger.setAttribute('aria-expanded', 'false');
      menu.setAttribute('aria-hidden', 'true');
    }

    trigger.addEventListener('click', function (event) {
      event.stopPropagation();
      var willOpen = !switcher.classList.contains('is-open');
      closeAllDropdowns(); // close everything first (including help-switch)
      if (willOpen) {
        switcher.classList.add('is-open');
        trigger.setAttribute('aria-expanded', 'true');
        menu.setAttribute('aria-hidden', 'false');
      }
    });

    options.forEach(function (option) {
      option.addEventListener('click', function () {
        lang = option.getAttribute('data-lang-option');
        localStorage.setItem(STORAGE_KEY, lang);
        applyLanguage(lang);
        closeMenu();
      });
    });

    document.addEventListener('click', function (event) {
      if (!switcher.contains(event.target)) closeMenu();
    });
  });

  document.querySelectorAll('[data-help-switch]').forEach(function (switcher) {
    var trigger = switcher.querySelector('.help-switch__trigger');
    var menu = switcher.querySelector('.help-switch__menu');

    function closeMenu() {
      switcher.classList.remove('is-open');
      trigger.setAttribute('aria-expanded', 'false');
      menu.setAttribute('aria-hidden', 'true');
    }

    trigger.addEventListener('click', function (event) {
      event.stopPropagation();
      var willOpen = !switcher.classList.contains('is-open');
      closeAllDropdowns(); // close everything first (including lang-switch)
      if (willOpen) {
        switcher.classList.add('is-open');
        trigger.setAttribute('aria-expanded', 'true');
        menu.setAttribute('aria-hidden', 'false');
      }
    });

    document.addEventListener('click', function (event) {
      if (!switcher.contains(event.target)) closeMenu();
    });
  });

  applyLanguage(lang);
})();
