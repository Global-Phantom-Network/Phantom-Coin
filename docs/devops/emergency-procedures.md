# Emergency Procedures

Incident-Response-Runbooks für kritische Situationen bei Phantom Coin Nodes.

## 🚨 Emergency Response Overview

| Severity | Response Time | Escalation |
|----------|--------------|------------|
| **P0 - Critical** | < 15 min | Immediate (all hands) |
| **P1 - High** | < 1 hour | On-call engineer |
| **P2 - Medium** | < 4 hours | Regular schedule |
| **P3 - Low** | < 24 hours | Next business day |

---

## Quick Reference

### Critical Issues (P0)

- [Node Down / Not Responding](#node-down--not-responding)
- [Consensus Halt / No Blocks](#consensus-halt--no-blocks)
- [Data Corruption](#data-corruption)
- [Security Breach](#security-breach)
- [Network Partition](#network-partition)

### High Priority Issues (P1)

- [High Memory Usage / OOM](#high-memory-usage--oom)
- [Slow Block Production](#slow-block-production)
- [P2P Connection Issues](#p2p-connection-issues)
- [Disk Space Critical](#disk-space-critical)

---

## Node Down / Not Responding

### Symptoms
- Health check failing
- No response from API
- Service status: `inactive (dead)`

### Immediate Actions

```bash
# 1. Check service status
systemctl status phantom-node

# 2. Check logs for crash reason
journalctl -u phantom-node --since "30 minutes ago" | tail -100

# 3. Quick restart (if safe)
systemctl restart phantom-node

# 4. Monitor startup
journalctl -u phantom-node -f
```

### Root Cause Analysis

```bash
# Check system resources
free -h
df -h
uptime

# Check for OOM kills
dmesg | grep -i "out of memory"
journalctl --since "1 hour ago" | grep -i "killed process"

# Check core dumps
ls -lh /var/crash/
coredumpctl list

# Check binary integrity
md5sum /usr/local/bin/phantom-node
```

### Recovery Steps

#### Scenario A: Clean restart works

```bash
# 1. Verify health
curl http://localhost:18081/healthz

# 2. Check block height progressing
STATUS_TOKEN=$(sudo cat /etc/phantom-coin/status-auth.token)
watch -n 5 "curl -s -H 'Authorization: Bearer $STATUS_TOKEN' http://localhost:18081/status | jq '.height'"

# 3. Monitor for 30 minutes
# → If stable, close incident
```

#### Scenario B: Crash on startup

```bash
# 1. Enable verbose logging
sudo systemctl edit phantom-node
# Add: Environment="RUST_LOG=debug"
# Add: Environment="RUST_BACKTRACE=full"

sudo systemctl restart phantom-node

# 2. Collect crash logs
journalctl -u phantom-node --since "now" > crash-$(date +%s).log

# 3. Try with fresh state (ONLY if data corrupted)
sudo systemctl stop phantom-node
sudo mv /var/lib/phantom/data /var/lib/phantom/data.corrupted
sudo systemctl start phantom-node

# → If still failing, escalate to P0 incident
```

#### Scenario C: Binary corrupted

```bash
# 1. Restore from backup or re-download
sudo cp /usr/local/bin/phantom-node.backup /usr/local/bin/phantom-node

# Or: Re-download verified binary
wget https://github.com/Global-Phantom-Network/Phantom-Coin/releases/download/v0.0.12/phantomcoin-v0.0.12-linux-x86_64.tar.gz
# ... verify & install ...

# 2. Restart
sudo systemctl restart phantom-node
```

---

## Consensus Halt / No Blocks

### Symptoms
- Block height not progressing
- Last block > 5 minutes ago
- Finality stalled

### Immediate Actions

```bash
# 1. Check local node status
STATUS_TOKEN=$(sudo cat /etc/phantom-coin/status-auth.token)
curl -H "Authorization: Bearer $STATUS_TOKEN" http://localhost:18081/status | jq '{height, last_block_time, finalized_height}'

# 2. Check other validators
for node in validator1 validator2 validator3; do
  echo "=== $node ==="
  ssh $node 'STATUS_TOKEN=$(sudo cat /etc/phantom-coin/status-auth.token); curl -s -H "Authorization: Bearer $STATUS_TOKEN" http://localhost:18081/status | jq ".height"'
done

# 3. Check network partition
ping validator1.example.com
ping validator2.example.com
traceroute validator1.example.com
```

### Diagnosis

```bash
# Is it local or network-wide?
# - If only your node stuck → local issue
# - If 33%+ stuck → network consensus issue

# Check P2P connectivity
STATUS_TOKEN=$(sudo cat /etc/phantom-coin/status-auth.token)
curl -H "Authorization: Bearer $STATUS_TOKEN" http://localhost:18081/metrics | grep pc_p2p_peers_total

# Check consensus logs
journalctl -u phantom-node | grep -i "consensus\|quorum\|finality"
```

### Recovery Steps

#### If LOCAL issue:

```bash
# 1. Restart node
systemctl restart phantom-node

# 2. If restart fails, resync from checkpoint
systemctl stop phantom-node
# Download latest checkpoint
wget https://snapshots.phantom.network/latest.tar.gz
tar -xzf latest.tar.gz -C /var/lib/phantom/data/
systemctl start phantom-node
```

#### If NETWORK-WIDE issue:

```bash
# 1. Coordinate with other validators (Slack/Discord)
# 2. Check if 67%+ can be brought online
# 3. If coordinated restart needed:

# Set restart time (all validators sync clocks)
RESTART_TIME="2025-11-09T18:00:00Z"

# At agreed time:
systemctl restart phantom-node

# Monitor consensus recovery
STATUS_TOKEN=$(sudo cat /etc/phantom-coin/status-auth.token)
watch -n 5 "curl -s -H 'Authorization: Bearer $STATUS_TOKEN' http://localhost:18081/status | jq '.finalized_height'"
```

---

## Data Corruption

### Symptoms
- DB read/write errors in logs
- Checksum mismatches
- Crash loop with "corrupted data" errors

### Immediate Actions

```bash
# 1. Stop node immediately
systemctl stop phantom-node

# 2. Check filesystem
df -h
sudo fsck -n /dev/sda1  # read-only check

# 3. Backup current state
sudo tar -czf /backup/phantom-corrupted-$(date +%s).tar.gz /var/lib/phantom/data/
```

### Recovery Steps

#### Option A: Repair DB (if possible)

```bash
# Check if phantom-node has repair tool
phantom-node repair --data-dir /var/lib/phantom/data/

# If repair succeeds:
systemctl start phantom-node
```

#### Option B: Restore from backup

```bash
# 1. Find latest good backup
ls -lht /backup/phantom-*

# 2. Restore
systemctl stop phantom-node
sudo rm -rf /var/lib/phantom/data/
sudo tar -xzf /backup/phantom-2025110915.tar.gz -C /

# 3. Start and verify
systemctl start phantom-node
journalctl -u phantom-node -f
```

#### Option C: Full resync (last resort)

```bash
# 1. Remove corrupted data
systemctl stop phantom-node
sudo rm -rf /var/lib/phantom-coin/data/*

# 2. Restore canonical genesis
sudo mkdir -p /var/lib/phantom-coin/data/mempool
sudo install -m 0644 /backup/genesis_note.bin /etc/phantom-coin/genesis_note.bin
sudo install -m 0644 /backup/genesis_note.bin /var/lib/phantom-coin/data/mempool/genesis_note.bin
# Expected canonical network_id after reset:
# d4d309537274b9f8e0c8e5a067d6f8b9ba898773bcd203e8e106db08ed9023f6

# 3. Start fresh sync
systemctl start phantom-node

# → Will take hours/days depending on chain length
```

---

## Security Breach

### Symptoms
- Unauthorized access detected
- Suspicious transactions
- Unexpected key usage
- Intrusion detection alerts

### Immediate Actions (DO NOT SKIP)

```bash
# 1. ISOLATE node immediately
sudo iptables -A INPUT -j DROP
sudo iptables -A OUTPUT -j DROP
# Keep SSH open for you:
sudo iptables -I INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -I OUTPUT -p tcp --sport 22 -j ACCEPT

# 2. STOP service
systemctl stop phantom-node

# 3. SNAPSHOT current state (forensics)
sudo tar -czf /forensics/phantom-breach-$(date +%s).tar.gz \
  /var/lib/phantom/ \
  /var/log/ \
  /etc/phantom/

# 4. ROTATE all credentials
# - SSH keys
# - API tokens
# - HSM keys (if compromised)
```

### Forensics

```bash
# 1. Check for unauthorized access
last -20
lastlog
who
w

# 2. Check suspicious processes
ps auxf | grep phantom
lsof -i -n -P

# 3. Check file modifications
find /var/lib/phantom -type f -mtime -1 -ls
find /usr/local/bin -type f -mtime -1 -ls

# 4. Check network connections
netstat -antp
ss -tulpn

# 5. Scan for rootkits (if suspected)
sudo rkhunter --check
sudo chkrootkit
```

### Recovery

```bash
# 1. Reinstall from VERIFIED source
sudo apt purge phantom-node  # or remove binary
wget https://github.com/Global-Phantom-Network/Phantom-Coin/releases/download/v0.0.12/...
# Verify checksums & signatures!
sudo dpkg -i phantom-node_0.0.12.deb

# 2. Restore CLEAN data (from before breach)
sudo rm -rf /var/lib/phantom/data/
sudo tar -xzf /backup/pre-breach-backup.tar.gz -C /

# 3. Harden system
sudo ufw enable
sudo ufw allow 22/tcp
sudo ufw allow 18081/tcp
sudo fail2ban-client start

# 4. Restore network access
sudo iptables -F

# 5. Start with monitoring
systemctl start phantom-node
journalctl -u phantom-node -f
```

### Post-Incident

```bash
# 1. Incident report
# 2. Security audit
# 3. Update security procedures
# 4. Notify community (if validators affected)
```

---

## High Memory Usage / OOM

### Symptoms
- Memory usage > 90%
- OOM killer active
- Slow response times
- Swap thrashing

### Immediate Actions

```bash
# 1. Check memory usage
free -h
ps aux --sort=-%mem | head -20

# 2. Check for memory leaks
pmap $(pgrep phantom-node) | tail -1

# 3. Emergency: Drop caches (temporary relief)
sync
echo 3 | sudo tee /proc/sys/vm/drop_caches

# 4. If critical: restart node
systemctl restart phantom-node
```

### Mitigation

```bash
# 1. Limit memory usage (systemd)
sudo systemctl edit phantom-node

# Add:
[Service]
MemoryMax=8G
MemoryHigh=7G

sudo systemctl daemon-reload
sudo systemctl restart phantom-node

# 2. Enable memory monitoring
# Add to /etc/prometheus/node_exporter.yml

# 3. Set up alerts
# - Memory > 80%: Warning
# - Memory > 90%: Critical
```

---

## Slow Block Production

### Symptoms
- Block time > expected (>10s for 5s target)
- High latency in consensus
- Timeouts in logs

### Quick Diagnosis

```bash
# 1. Check system load
uptime
top -b -n 1 | head -20

# 2. Check disk I/O
iostat -x 5 3
iotop -o

# 3. Check network latency
ping -c 10 validator1.example.com
mtr validator1.example.com

# 4. Check consensus metrics
STATUS_TOKEN=$(sudo cat /etc/phantom-coin/status-auth.token)
curl -H "Authorization: Bearer $STATUS_TOKEN" http://localhost:18081/metrics | grep -E "consensus|block_time"
```

### Mitigation

```bash
# Scenario A: High CPU
# → Check for resource-intensive queries/txs
# → Increase CPU allocation or move to bigger instance

# Scenario B: Slow disk
# → Switch to SSD if on HDD
# → Check for disk errors: smartctl -a /dev/sda

# Scenario C: Network issues
# → Check bandwidth: iftop
# → Check firewall rules
# → Contact ISP if needed

# Scenario D: Software bug
# → Enable profiling
# → Collect flamegraph
# → Report issue with diagnostics
```

---

## P2P Connection Issues

### Symptoms
- Peer count = 0
- "No peers available" in logs
- Isolated from network

### Quick Fix

```bash
# 1. Check firewall
sudo ufw status
sudo iptables -L -n

# 2. Check P2P port open
nc -zv localhost 30333  # Replace with actual P2P port

# 3. Restart with fresh peer list
systemctl stop phantom-node
rm -f /var/lib/phantom/peers.db
systemctl start phantom-node

# 4. Monitor peer connections
STATUS_TOKEN=$(sudo cat /etc/phantom-coin/status-auth.token)
watch -n 5 "curl -s -H 'Authorization: Bearer $STATUS_TOKEN' http://localhost:18081/metrics | grep pc_p2p_peers_total"
```

---

## Disk Space Critical

### Symptoms
- Disk usage > 90%
- "No space left on device" errors
- Write failures

### Emergency Cleanup

```bash
# 1. Find large files/dirs
du -sh /* | sort -rh | head -20
du -sh /var/lib/phantom/* | sort -rh

# 2. Emergency cleanup
# - Rotate logs
journalctl --vacuum-time=7d
rm -f /var/log/*.gz

# - Clear old backups (be careful!)
find /backup -type f -mtime +30 -delete

# - Clear tmp files
rm -rf /tmp/*
rm -rf /var/tmp/*

# 3. Extend disk (if VM)
# - Resize volume in cloud console
# - Resize partition: growpart /dev/sda 1
# - Resize filesystem: resize2fs /dev/sda1
```

### Long-term Solution

```bash
# 1. Set up log rotation
cat > /etc/logrotate.d/phantom-node <<EOF
/var/log/phantom-node/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifexist
    create 0640 phantom phantom
}
EOF

# 2. Archive old chain data
# - Implement pruning if available
# - Move to archive storage

# 3. Set up monitoring alerts
# - Disk > 80%: Warning
# - Disk > 90%: Critical
```

---

## Network Partition

### Symptoms
- Cannot reach 50%+ of validators
- Consensus stalled
- "Network unreachable" errors

### Diagnosis

```bash
# 1. Check internet connectivity
ping 8.8.8.8
curl -I https://google.com

# 2. Check validator connectivity
for node in validator1 validator2 validator3; do
  ping -c 3 $node.example.com
  nc -zv $node.example.com 30333
done

# 3. Check routing
traceroute validator1.example.com

# 4. Check DNS
dig validator1.example.com
nslookup validator1.example.com
```

### Recovery

```bash
# If local network issue:
# 1. Check firewall/routing
# 2. Restart networking
# 3. Contact ISP

# If datacenter/cloud issue:
# 1. Check cloud provider status page
# 2. Consider failover to backup region
# 3. Wait for resolution

# If split-brain (rare):
# 1. Coordinate with other validators
# 2. Identify majority partition
# 3. Minority nodes should stop until resolved
```

---

## Emergency Contacts

### On-Call Rotation

| Shift | Engineer | Phone | Backup |
|-------|----------|-------|--------|
| Mon-Wed | Alice | +1-555-0101 | Bob |
| Thu-Fri | Bob | +1-555-0102 | Charlie |
| Sat-Sun | Charlie | +1-555-0103 | Alice |

### Escalation Path

1. **On-Call Engineer** → 15 min response
2. **Team Lead** → 30 min response
3. **CTO** → 1 hour response
4. **All Hands** → Critical (P0) only

### Communication Channels

- **Emergency:** Slack #phantom-ops-emergency
- **Status:** status.phantom.network
- **GitHub:** https://github.com/Global-Phantom-Network/Phantom-Coin/issues
- **Community:** Discord #validator-support

---

## Post-Incident Review

### Template

```markdown
# Incident: [Brief Description]

**Date:** 2025-11-09
**Duration:** 2h 15m
**Severity:** P0
**Resolved By:** Alice, Bob

## Timeline
- 14:00 UTC: Alert triggered (node down)
- 14:05 UTC: On-call paged
- 14:15 UTC: Root cause identified (OOM)
- 16:15 UTC: Resolved (increased memory, node healthy)

## Root Cause
Out of memory due to memory leak in version v0.0.11.

## Resolution
- Restarted node with increased memory
- Applied hotfix v0.0.11.1
- Monitoring confirmed stable

## Action Items
- [ ] Deploy v0.0.11.1 to all nodes
- [ ] Add memory alerts at 80%
- [ ] Investigate memory leak (issue #123)
- [ ] Update runbooks

## Lessons Learned
- Need better memory monitoring
- Consider memory limits in systemd
```

---

## Siehe auch

- [Upgrade Procedures](./upgrade-procedures.md)
- [Docker Compose Guide](./docker-compose.md)
- [Monitoring Setup](../observability/README.md)
