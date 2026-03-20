/** Detect Tauri runtime vs plain browser */
export const isTauri = typeof window !== 'undefined' && '__TAURI_IPC__' in window;

function isLoopbackHost(host: string): boolean {
  const h = host.trim().toLowerCase();
  return h === 'localhost' || h === '127.0.0.1' || h === '::1';
}

function isLoopbackHttpUrl(url: string): boolean {
  try {
    const u = new URL(url);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') {
      return false;
    }
    return isLoopbackHost(u.hostname);
  } catch {
    return false;
  }
}

function guardBrowserBearerTarget(url: string, bearerToken: string): void {
  if (!bearerToken) {
    return;
  }
  if (!isLoopbackHttpUrl(url)) {
    throw new Error('Refusing to send bearer token to non-loopback URL in browser mode.');
  }
}

/**
 * Browser-compatible HTTP GET.
 * In Tauri: uses invoke('http_get') to bypass CORS.
 * In Browser: uses fetch() directly.
 */
export async function httpGet(url: string, bearerToken: string): Promise<string> {
  if (isTauri) {
    const { invoke } = await import('@tauri-apps/api/tauri');
    return await invoke<string>('http_get', {
      args: { url, bearer_token: bearerToken || null },
    });
  }
  guardBrowserBearerTarget(url, bearerToken);
  const headers: Record<string, string> = {};
  if (bearerToken) {
    headers['Authorization'] = `Bearer ${bearerToken}`;
  }
  const resp = await fetch(url, { headers });
  if (!resp.ok) {
    throw new Error(`HTTP ${resp.status}: ${resp.statusText}`);
  }
  return await resp.text();
}

export async function httpGetFast(url: string, bearerToken: string, timeoutMs: number): Promise<string> {
  if (isTauri) {
    const { invoke } = await import('@tauri-apps/api/tauri');
    return await invoke<string>('http_get', {
      args: { url, bearer_token: bearerToken || null, timeout_ms: timeoutMs },
    });
  }
  guardBrowserBearerTarget(url, bearerToken);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const headers: Record<string, string> = {};
    if (bearerToken) {
      headers['Authorization'] = `Bearer ${bearerToken}`;
    }
    const resp = await fetch(url, { headers, signal: controller.signal });
    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status}: ${resp.statusText}`);
    }
    return await resp.text();
  } finally {
    clearTimeout(timer);
  }
}

function tauriOnly(name: string): never {
  throw new Error(`"${name}" ist nur in der Tauri-Desktop-App verfügbar, nicht im Browser.`);
}

export async function listListenPorts(): Promise<{ port: number; process: string | null }[]> {
  if (!isTauri) return [];
  const { invoke } = await import('@tauri-apps/api/tauri');
  return await invoke('list_listen_ports');
}

export async function appQuit(): Promise<void> {
  if (!isTauri) { window.close(); return; }
  const { invoke } = await import('@tauri-apps/api/tauri');
  await invoke('app_quit');
}

export async function walletGenerateMnemonic(): Promise<string> {
  if (!isTauri) tauriOnly('walletGenerateMnemonic');
  const { invoke } = await import('@tauri-apps/api/tauri');
  return await invoke('wallet_generate_mnemonic');
}

export async function walletCreate(args: unknown): Promise<unknown> {
  if (!isTauri) tauriOnly('walletCreate');
  const { invoke } = await import('@tauri-apps/api/tauri');
  return await invoke('wallet_create', { args });
}

export async function walletCreateWatchOnly(args: unknown): Promise<unknown> {
  if (!isTauri) tauriOnly('walletCreateWatchOnly');
  const { invoke } = await import('@tauri-apps/api/tauri');
  return await invoke('wallet_create_watch_only', { args });
}

export async function walletStatus(walletName: string): Promise<unknown> {
  if (!isTauri) tauriOnly('walletStatus');
  const { invoke } = await import('@tauri-apps/api/tauri');
  return await invoke('wallet_status', { wallet_name: walletName });
}

export async function walletUnlock(walletName: string, passphrase: string): Promise<unknown> {
  if (!isTauri) tauriOnly('walletUnlock');
  const { invoke } = await import('@tauri-apps/api/tauri');
  return await invoke('wallet_unlock', { wallet_name: walletName, passphrase });
}

export async function walletLock(): Promise<void> {
  if (!isTauri) tauriOnly('walletLock');
  const { invoke } = await import('@tauri-apps/api/tauri');
  await invoke('wallet_lock');
}

export async function walletSelectAddr(walletName: string, addr: string): Promise<unknown> {
  if (!isTauri) tauriOnly('walletSelectAddr');
  const { invoke } = await import('@tauri-apps/api/tauri');
  return await invoke('wallet_select_addr', { args: { wallet_name: walletName, addr } });
}

export async function walletSend(args: unknown): Promise<unknown> {
  if (!isTauri) tauriOnly('walletSend');
  const { invoke } = await import('@tauri-apps/api/tauri');
  return await invoke('wallet_send', { args });
}

export async function walletBackupToDir(args: unknown): Promise<unknown> {
  if (!isTauri) tauriOnly('walletBackupToDir');
  const { invoke } = await import('@tauri-apps/api/tauri');
  return await invoke('wallet_backup_to_dir', { args });
}

export async function walletRestoreFromDir(args: unknown): Promise<unknown> {
  if (!isTauri) tauriOnly('walletRestoreFromDir');
  const { invoke } = await import('@tauri-apps/api/tauri');
  return await invoke('wallet_restore_from_dir', { args });
}

export async function walletHistoryCsvAppend(args: unknown): Promise<unknown> {
  if (!isTauri) tauriOnly('walletHistoryCsvAppend');
  const { invoke } = await import('@tauri-apps/api/tauri');
  return await invoke('wallet_history_csv_append', { args });
}

export async function walletHistoryCsvOpenFolder(args: unknown): Promise<unknown> {
  if (!isTauri) tauriOnly('walletHistoryCsvOpenFolder');
  const { invoke } = await import('@tauri-apps/api/tauri');
  return await invoke('wallet_history_csv_open_folder', { args });
}

export async function walletHistoryCsvRange(args: unknown): Promise<unknown> {
  if (!isTauri) tauriOnly('walletHistoryCsvRange');
  const { invoke } = await import('@tauri-apps/api/tauri');
  return await invoke('wallet_history_csv_range', { args });
}

export async function bitboxBridgeStatus(args: unknown): Promise<unknown> {
  if (!isTauri) tauriOnly('bitboxBridgeStatus');
  const { invoke } = await import('@tauri-apps/api/tauri');
  return await invoke('bitbox_bridge_status', { args });
}

export async function bitboxHwiEnumerate(args: unknown): Promise<unknown> {
  if (!isTauri) tauriOnly('bitboxHwiEnumerate');
  const { invoke } = await import('@tauri-apps/api/tauri');
  return await invoke('bitbox_hwi_enumerate', { args });
}

export async function bitboxHwiGetXpub(args: unknown): Promise<unknown> {
  if (!isTauri) tauriOnly('bitboxHwiGetXpub');
  const { invoke } = await import('@tauri-apps/api/tauri');
  return await invoke('bitbox_hwi_get_xpub', { args });
}

export async function validatorKeygenBls(args: unknown): Promise<unknown> {
  if (!isTauri) tauriOnly('validatorKeygenBls');
  const { invoke } = await import('@tauri-apps/api/tauri');
  return await invoke('validator_keygen_bls', { args });
}

export async function validatorBlsInfo(args: unknown): Promise<unknown> {
  if (!isTauri) tauriOnly('validatorBlsInfo');
  const { invoke } = await import('@tauri-apps/api/tauri');
  return await invoke('validator_bls_info', { args });
}

export async function validatorStakeBond(args: unknown): Promise<unknown> {
  if (!isTauri) tauriOnly('validatorStakeBond');
  const { invoke } = await import('@tauri-apps/api/tauri');
  return await invoke('validator_stake_bond', { args });
}

export async function validatorStakeUnbond(args: unknown): Promise<unknown> {
  if (!isTauri) tauriOnly('validatorStakeUnbond');
  const { invoke } = await import('@tauri-apps/api/tauri');
  return await invoke('validator_stake_unbond', { args });
}

export async function validatorRegister(args: unknown): Promise<unknown> {
  if (!isTauri) tauriOnly('validatorRegister');
  const { invoke } = await import('@tauri-apps/api/tauri');
  return await invoke('validator_register', { args });
}

export type BootstrapPeerDisk = { addr: string; cert_file: string };

export async function bootstrapPeersLoad(
  storeDir: string,
): Promise<{ path: string; peers: BootstrapPeerDisk[] }> {
  if (!isTauri) tauriOnly('bootstrapPeersLoad');
  const { invoke } = await import('@tauri-apps/api/tauri');
  return await invoke('bootstrap_peers_load', { args: { store_dir: storeDir } });
}

export async function bootstrapPeersSave(
  storeDir: string,
  peers: BootstrapPeerDisk[],
): Promise<{ path: string; peers_written: number }> {
  if (!isTauri) tauriOnly('bootstrapPeersSave');
  const { invoke } = await import('@tauri-apps/api/tauri');
  return await invoke('bootstrap_peers_save', { args: { store_dir: storeDir, peers } });
}

export type CanonicalGenesisResetPrepareResp = {
  ok: boolean;
  token: string;
  ready_at_unix_ms: number;
  network_id: string;
  already_active: boolean;
  message: string;
};

export type CanonicalGenesisResetCommitResp = {
  ok: boolean;
  network_id: string;
  already_active: boolean;
  genesis_note_path: string;
  backup_path: string | null;
  purged_items: string[];
  message: string;
};

export async function canonicalGenesisResetPrepare(args: {
  store_dir: string;
  confirm_text: string;
}): Promise<CanonicalGenesisResetPrepareResp> {
  if (!isTauri) tauriOnly('canonicalGenesisResetPrepare');
  const { invoke } = await import('@tauri-apps/api/tauri');
  return await invoke('node_canonical_genesis_reset_prepare', { args });
}

export async function canonicalGenesisResetCommit(args: {
  store_dir: string;
  token: string;
}): Promise<CanonicalGenesisResetCommitResp> {
  if (!isTauri) tauriOnly('canonicalGenesisResetCommit');
  const { invoke } = await import('@tauri-apps/api/tauri');
  return await invoke('node_canonical_genesis_reset_commit', { args });
}

export async function nodeStart(args: unknown): Promise<unknown> {
  if (!isTauri) tauriOnly('nodeStart');
  const { invoke } = await import('@tauri-apps/api/tauri');
  return await invoke('node_start', { args });
}

export async function nodeStop(): Promise<void> {
  if (!isTauri) tauriOnly('nodeStop');
  const { invoke } = await import('@tauri-apps/api/tauri');
  await invoke('node_stop');
}

export async function nodeStatus(): Promise<unknown> {
  if (!isTauri) return { running: false, p2p_running: false, status_running: false, status_http_running: false, mint_rpc_running: false };
  const { invoke } = await import('@tauri-apps/api/tauri');
  return await invoke('node_status');
}

export async function nodeLogs(limit: number): Promise<string[]> {
  if (!isTauri) return [];
  const { invoke } = await import('@tauri-apps/api/tauri');
  return await invoke('node_logs', { args: { limit } });
}

export async function nodeBackupStore(args: unknown): Promise<unknown> {
  if (!isTauri) tauriOnly('nodeBackupStore');
  const { invoke } = await import('@tauri-apps/api/tauri');
  return await invoke('node_backup_store', { args });
}

export async function nodeWalletUtxosByLock(lockHex: string): Promise<string> {
  if (!isTauri) tauriOnly('nodeWalletUtxosByLock');
  const { invoke } = await import('@tauri-apps/api/tauri');
  return await invoke('node_wallet_utxos_by_lock', { args: { lock_hex: lockHex } });
}

export async function nodeWalletHistory(lockHex: string): Promise<string> {
  if (!isTauri) tauriOnly('nodeWalletHistory');
  const { invoke } = await import('@tauri-apps/api/tauri');
  return await invoke('node_wallet_history', { args: { lock_hex: lockHex } });
}

export async function nodeConsensusValidators(): Promise<string> {
  if (!isTauri) tauriOnly('nodeConsensusValidators');
  const { invoke } = await import('@tauri-apps/api/tauri');
  return await invoke('node_consensus_validators');
}
