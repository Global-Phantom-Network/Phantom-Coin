export type Locale = 'de' | 'en' | 'es' | 'fr' | 'it' | 'pt' | 'nl' | 'ru' | 'zh' | 'ja' | 'ko' | 'tr' | 'ar' | 'pl';

export interface DashboardTexts {
  // --- Header / Navigation ---
  appTitle: string;
  online: string;
  offline: string;
  appQuit: string;
  tabNode: string;
  tabMiner: string;
  tabValidators: string;
  tabWallet: string;
  tabLogs: string;
  settings: string;

  // --- Allgemein ---
  start: string;
  stop: string;
  backup: string;
  refresh: string;
  save: string;
  cancel: string;
  close: string;
  error: string;
  hint: string;
  noData: string;
  loading: string;
  ok: string;
  down: string;
  running: string;
  stopped: string;
  active: string;
  inactive: string;
  connecting: string;
  tauriOnly: string;
  showMore: string;

  // --- Node-Tab ---
  nodeTitle: string;
  nodeSince: string;
  nodeBackupTargetEmpty: string;
  nodeBackupCreated: string;
  nodeBackupFailed: string;
  nodeValidatorPassphrase: string;
  nodeValidatorPassphraseHint: string;
  nodePassphraseRole: string;
  nodeBearerTokenHint: string;

  // --- Node KPIs ---
  kpiStatusServeAddr: string;
  kpiStatusHttpAddr: string;
  kpiMintRpcAddr: string;
  kpiP2PListen: string;
  kpiStore: string;
  kpiMetricsAddr: string;

  // --- P2P Netzwerk ---
  p2pTitle: string;
  p2pPeers: string;
  p2pMiners: string;
  p2pValidator: string;
  p2pSent: string;
  p2pReceived: string;
  p2pKnown: string;
  p2pBanned: string;
  p2pOutboxDepth: string;

  // --- Mempool & Proposer ---
  mempoolTitle: string;
  mempoolMintPropagation: string;
  mempoolSize: string;
  mempoolAcceptedRejected: string;
  mempoolDuplicate: string;
  mempoolEvicted: string;
  mempoolInvalidated: string;
  mempoolProposerBuilt: string;
  mempoolProposerPending: string;

  // --- Charts ---
  chartP2PTraffic: string;
  chartNetworkTps: string;
  chartTpsSubtitle: string;
  chartVerifyHeatmap: string;
  chartVerifyAvg: string;

  // --- Stats ---
  statInboundRate: string;
  statOutboundRate: string;
  statRpcBroadcastTotal: string;
  statRpcBroadcastErrors: string;

  // --- Miner-Tab ---
  minerTitle: string;
  minerStart: string;
  minerStop: string;
  minerRunning: string;
  minerStopped: string;
  minerWaiting: string;
  minerConfigTitle: string;
  minerRewardTo: string;
  minerSubmitTitle: string;
  minerHashrate: string;
  minerUptime: string;
  minerHashes: string;
  minerLastMine: string;
  minerDifficulty: string;
  minerSubmitOk: string;
  minerSubmitStale: string;
  minerSubmitRejected: string;
  minerSubmitErrors: string;
  minerRejectRate: string;
  minerTemplateTitle: string;
  minerTemplateOk: string;
  minerTemplateErrors: string;
  minerLastTemplate: string;
  minerThreads: string;
  minerLogsTitle: string;

  // --- Validators-Tab ---
  validatorsTitle: string;
  validatorsEligible: string;
  validatorsTotalStake: string;
  validatorsMinStake: string;
  validatorsVotesSent: string;
  validatorsVotesAccepted: string;
  validatorsVotesRejected: string;
  validatorsVotesPerMin: string;
  validatorsList: string;
  validatorsAsOf: string;
  validatorsRefresh: string;
  validatorsNoneFound: string;
  validatorsStatus: string;
  validatorsFinalityAvg: string;
  validatorsFinalityEvents: string;
  validatorsFinalityMints: string;
  validatorsMintHeight: string;
  validatorsConsensusTitle: string;
  validatorsVerifyAvg: string;
  validatorsVerifySamples: string;
  validatorsConsensusErrors: string;
  validatorsBlsKeystore: string;
  validatorsPassphrase: string;
  validatorsPassphraseConfirm: string;
  validatorsForce: string;
  validatorsPassphraseRole: string;
  validatorsPassphraseMinLen: string;
  validatorsPassphraseMismatch: string;
  validatorsStakeBonding: string;
  validatorsLoadUtxos: string;
  validatorsSelectAllUnstaked: string;
  validatorsSelectAllStaked: string;
  validatorsNoUtxosSelected: string;
  validatorsSelectStakedUtxo: string;
  validatorsRegister: string;
  validatorsRegisterHint: string;
  validatorsEndpointUnavailable: string;

  // --- Wallet-Tab ---
  walletMintLockWarning: string;
  walletLive: string;
  walletOffline: string;
  walletUpdated: string;
  walletBalance: string;
  walletStaked: string;
  walletUtxos: string;
  walletLocalTitle: string;
  walletCreate: string;
  walletUnlock: string;
  walletLock: string;
  walletLocked: string;
  walletPassphrase: string;
  walletWalletName: string;
  walletSelectAddress: string;
  walletReceiveAddress: string;
  walletCopyAddress: string;
  walletCopied: string;
  walletLockHex: string;
  walletSend: string;
  walletSendFrom: string;
  walletSendTo: string;
  walletSendAmount: string;
  walletSendFee: string;
  walletBack: string;
  walletSeedPhraseTitle: string;
  walletSeedStep1: string;
  walletSeedStep2: string;
  walletSeedStep3: string;
  walletSeedWord: string;
  walletSeedGenerate: string;
  walletSeedGenerating: string;
  walletSeedGenerated: string;
  walletSeedVerifyNext: string;
  walletSeedVerifyFinish: string;
  walletSeedFillAll: string;
  walletSeedWrongWords: string;
  walletSeedConfirmed: string;
  walletSeedConfirmedLabel: string;
  walletHotwalletWarningTitle: string;
  walletHotwalletWarning1: string;
  walletHotwalletWarning2: string;
  walletHotwalletWarning3: string;
  walletHotwalletWarning4: string;
  walletPasswordLabel: string;
  walletShowPassphrase: string;
  walletPassphraseOk: string;
  walletPassphraseHint: string;
  walletCreating: string;
  walletCreated: string;
  walletCreateButton: string;

  // --- BitBox02 ---
  walletBitboxBridgeCheck: string;
  walletBitboxDetect: string;
  walletBitboxNotFound: string;
  walletBitboxNotRecognized: string;
  walletBitboxXpubOk: string;
  walletBitboxReadXpub: string;

  // --- Einstellungen ---
  settingsTitle: string;
  settingsTabConnection: string;
  settingsTabNode: string;
  settingsTabBitbox: string;
  settingsTabWallet: string;
  settingsStatusUrl: string;
  settingsMetricsPrimary: string;
  settingsMetricsFallback: string;
  settingsBearerToken: string;
  settingsAutoDetect: string;
  settingsNodeBase: string;
  settingsNodeLocalAddr: string;
  settingsNodeStoreDir: string;
  settingsChooseDir: string;
  settingsNodeP2PAddr: string;
  settingsNodeP2PPublic: string;
  settingsGenesisRoles: string;
  settingsEnableTxProposer: string;
  settingsEnablePowMiner: string;
  settingsValidatorControlOverride: string;
  settingsValidatorId: string;
  settingsBlsPubKey: string;
  settingsMintAmount: string;
  settingsMintLock: string;
  settingsBootstrapPeers: string;
  settingsFile: string;
  settingsLoad: string;
  settingsAddPeer: string;
  settingsPeerAddress: string;
  settingsPeerCert: string;
  settingsNoPeers: string;
  settingsRemove: string;
  settingsBackup: string;
  settingsBackupTarget: string;
  settingsActions: string;
  settingsBootstrapGenesisActivate: string;
  settingsBridgeCheck: string;
  settingsCreateBackup: string;
  settingsRestoreSource: string;
  settingsForceOverwrite: string;
  settingsRestore: string;
  settingsOpenFolder: string;
  settingsFrom: string;
  settingsTo: string;
  settingsCsvDownload: string;
  settingsCsvExporting: string;
  settingsCsvNoEvents: string;
  settingsCsvExported: string;
  settingsBootstrapDangerTitle: string;
  settingsBootstrapWarning: string;
  settingsBootstrapConfirmLabel: string;
  settingsBootstrapNetworkId: string;
  settingsBootstrapReady: string;
  settingsBootstrapStep1: string;
  settingsBootstrapStep2: string;

  // --- Logs ---
  logsNodeTitle: string;
  logsNetworkTitle: string;
  logsNetworkSubtitle: string;
  logsSystemTitle: string;
  logsSystemSubtitle: string;
  logsMinerTitle: string;
  logsMinerSubtitle: string;
  logsValidatorTitle: string;
  logsValidatorSubtitle: string;
  logsDashboardTitle: string;
  logsEmpty: string;

  // --- Panel Info Tooltips ---
  infoNode: string;
  infoP2p: string;
  infoMempool: string;
  infoChartP2p: string;
  infoChartTps: string;
  infoChartHeatmap: string;
  infoMiner: string;
  infoMinerSubmit: string;
  infoMinerTemplate: string;
  infoValidatorsList: string;
  infoConsensus: string;
  infoBlsKeystore: string;
  infoStakeBonding: string;
  infoValidatorRegister: string;
  infoWalletLocal: string;
  infoLogs: string;

  // --- Sprache ---
  language: string;
}

export const LOCALE_NAMES: Record<Locale, string> = {
  de: 'Deutsch',
  en: 'English',
  es: 'Español',
  fr: 'Français',
  it: 'Italiano',
  pt: 'Português',
  nl: 'Nederlands',
  ru: 'Русский',
  zh: '简体中文',
  ja: '日本語',
  ko: '한국어',
  tr: 'Türkçe',
  ar: 'العربية',
  pl: 'Polski',
};
