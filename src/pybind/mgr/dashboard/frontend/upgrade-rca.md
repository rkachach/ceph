# Root Cause Analysis: Upgrade Fails via Dashboard but Passes via CLI

## TL;DR

**Both CLI and Dashboard call the exact same orchestrator code.** The failure is NOT caused by different code paths between CLI and Dashboard. The failure is caused by a **stale Prometheus template cached in the config-key store** that breaks when the new MGR code (9.1) tries to render it with a changed context dictionary. **Both CLI and Dashboard upgrades WILL hit this error on any cluster that has this stale template.** If CLI appeared to pass, the template was either already cleared on that cluster or the error was silently swallowed by `_check_daemons`.

---

## 1. Architecture: How Upgrade Works

### 1.1 Entry Points (IDENTICAL for CLI and Dashboard)

```
CLI PATH:
  User runs: ceph orch upgrade start --image <image>
  → module.py:4779 upgrade_start()
    → upgrade.py:913 self.upgrade.upgrade_start(image, version, ...)
      → Saves UpgradeState to store
      → Returns "Started upgrade to <image>"

DASHBOARD PATH:
  User clicks "Start Upgrade" with custom image
  → Frontend: upgrade-start-modal.component.ts:77
    → upgradeService.start(version, image, licenseAccepted)
      → HTTP POST /api/cluster/upgrade/start
        → cluster.py:66 ClusterUpgrade.start()
          → orch.upgrades.start(image, version, ...)
            → module.py:4779 upgrade_start() ← SAME FUNCTION
              → upgrade.py:913 self.upgrade.upgrade_start(image, version, ...)
                → Saves UpgradeState to store
                → Returns "Started upgrade to <image>"
```

**Both paths call `self.upgrade.upgrade_start()` in upgrade.py:913. Identical.**

Neither path directly executes any upgrade logic. They ONLY save state. The actual upgrade runs asynchronously in the background serve loop.

### 1.2 The Background Serve Loop (serve.py:81-166)

This loop runs continuously in the cephadm MGR module, regardless of whether the upgrade was started via CLI or Dashboard:

```
┌─────────────────────────────────────────────────────────┐
│                 serve() main loop                        │
│                                                          │
│  while self.mgr.run:                                     │
│    ┌──────────────────────────────────────────────────┐   │
│    │ 1. _refresh_hosts_and_daemons()        line 101  │   │
│    │ 2. _check_for_strays()                 line 103  │   │
│    │ 3. _update_paused_health()             line 105  │   │
│    │                                                  │   │
│    │ if not self.mgr.paused:                          │   │
│    │   4. _run_async_actions()              line 115  │   │
│    │   5. _apply_all_services()             line 127  │   │
│    │   6. _handle_osd_rebuilds()            line 135  │   │
│    │                                                  │   │
│    │   7. ★ _check_daemons()               line 137  │◄──── RUNS FIRST
│    │                                                  │   │
│    │   8.   _check_certificates()           line 139  │   │
│    │   9.   _purge_deleted_services()       line 141  │   │
│    │  10.   _check_for_moved_osds()         line 143  │   │
│    │  11.   _retry_failed_operations()      line 145  │   │
│    │                                                  │   │
│    │  12. ★ continue_upgrade()             line 153  │◄──── RUNS SECOND
│    │                                                  │   │
│    └──────────────────────────────────────────────────┘   │
│    _serve_sleep()                                        │
└─────────────────────────────────────────────────────────┘
```

**CRITICAL:** `_check_daemons()` at line 137 runs BEFORE `continue_upgrade()` at line 153 **on every single loop iteration**. This ordering is the same regardless of how the upgrade was initiated.

---

## 2. The Upgrade Order

Defined in `utils.py:24-32`:

```python
CEPH_TYPES = ['mgr', 'mon', 'crash', 'osd', 'mds', 'rgw', 'rbd-mirror', 'cephfs-mirror', 'ceph-exporter']
GATEWAY_TYPES = ['iscsi', 'nfs', 'nvmeof', 'smb']
MONITORING_STACK_TYPES = ['node-exporter', 'prometheus', 'alertmanager', 'grafana', 'loki', 'promtail', 'alloy']
CEPH_UPGRADE_ORDER = CEPH_TYPES + GATEWAY_TYPES + MONITORING_STACK_TYPES + [...]
```

Upgrade order:
```
Position  0: mgr          ← FIRST
Position  1: mon
Position  2: crash
Position  3: osd
Position  4: mds
Position  5: rgw
Position  6: rbd-mirror
Position  7: cephfs-mirror
Position  8: ceph-exporter
Position  9: iscsi
Position 10: nfs
Position 11: nvmeof
Position 12: smb
Position 13: node-exporter
Position 14: prometheus    ← NEAR LAST (monitoring stack)
Position 15: alertmanager
Position 16: grafana
...
```

**MGR upgrades FIRST. Prometheus upgrades near the END.**

---

## 3. The Root Cause: Stale Template in Config-Key Store

### 3.1 The Template System (template.py:61-109)

When `generate_config()` renders the prometheus.yml, it goes through `TemplateMgr.render()`:

```python
# template.py:69-109
def render(self, name, context=None, managed_context=True, host=None):
    ctx = {**self.base_context, **context}

    # Check config-key store for custom/cached template
    store_name = name.rstrip('.j2')   # "services/prometheus/prometheus.yml"
    custom_template = self.mgr.get_store(store_name, None)

    if custom_template:                              # ← IF CACHED TEMPLATE EXISTS
        return self.engine.render_plain(custom_template, ctx)   # USE IT
    else:
        return self.engine.render(name, ctx)          # else use .j2 from disk
```

### 3.2 How the Template Gets Cached

In `monitoring.py:612-626`, during `generate_config()`:

```python
config_key = 'services/prometheus/prometheus.yml'
existing_config = self.mgr.get_store(config_key)

if existing_config is None:
    # First time: cache the RAW .j2 template into config-key store
    loader = self.mgr.template.engine.env.loader
    raw_template, _, _ = loader.get_source(
        self.mgr.template.engine.env,
        'services/prometheus/prometheus.yml.j2'
    )
    self.mgr.set_store(config_key, raw_template)   # ← CACHED FOREVER
```

**This only writes if `existing_config is None`.** Once cached, it is NEVER updated by the upgrade process.

### 3.3 The Template Mismatch

**7.1 template** (cached in config-key store from when cluster was on 7.1):
```jinja2
{% if alertmanager_sd_url %}
alerting:
  alertmanagers:
    - http_sd_configs:
        - url: {{ alertmanager_sd_url }}
...
```

**9.1 template** (on-disk .j2 in new MGR code):
```jinja2
{% if 'alertmanager' in service_discovery_cfg %}
alerting:
  alertmanagers:
    ...
    {% for url in service_discovery_cfg['alertmanager'] %}
      - url: {{ url }}
    {% endfor %}
```

**9.1 context** (from monitoring.py:584-599):
```python
context = {
    'service_discovery_cfg': self.get_service_discovery_cfg(...),
    'security_enabled': security_enabled,
    ...
    # NO 'alertmanager_sd_url' key!
}
```

### 3.4 The Crash

When the 9.1 MGR code renders prometheus.yml:
1. `TemplateMgr.render()` finds the **7.1 template** in config-key store
2. Uses `render_plain(old_template, new_context)`
3. Old template references `{{ alertmanager_sd_url }}`
4. New context has `service_discovery_cfg` but NOT `alertmanager_sd_url`
5. Jinja2 `StrictUndefined` mode → **`UndefinedError: 'alertmanager_sd_url' is undefined`**

---

## 4. Where the Error Manifests: Two Different Code Paths

### 4.1 Path A: `_check_daemons()` — SWALLOWS the error

```
serve.py:137  _check_daemons()
  ↓
serve.py:1466  deps = self.mgr._calc_daemon_deps(...)
serve.py:1478  elif last_deps != deps:
                 action = 'reconfig'
  ↓
serve.py:1581  self.mgr._daemon_action(daemon_spec, action='reconfig', ...)
  ↓
module.py:3099  if action == 'redeploy' or action == 'reconfig':
module.py:3105    daemon_spec = service_registry.get_service(svc_type).prepare_create(daemon_spec)
  ↓
cephadmservice.py:621  daemon_spec.final_config, daemon_spec.deps = self.generate_config(daemon_spec)
  ↓
monitoring.py:609  'prometheus.yml': self.mgr.template.render('services/prometheus/prometheus.yml.j2', context)
  ↓
template.py:107  return self.engine.render_plain(custom_template, ctx)  ← USES CACHED 7.1 TEMPLATE
  ↓
★ UndefinedError: 'alertmanager_sd_url' is undefined
  ↓
serve.py:1596  except Exception as e:
serve.py:1597    self.log.exception(e)              ← LOGGED
serve.py:1601    # continue...                      ← ★★★ SILENTLY SWALLOWED ★★★
```

**`_check_daemons` catches ALL exceptions from reconfig and continues.** The error is logged but does NOT stop the upgrade. Does NOT call `_fail_upgrade()`.

### 4.2 Path B: `continue_upgrade()` → `_do_upgrade()` — RAISES UPGRADE_EXCEPTION

```
serve.py:153   if self.mgr.upgrade.continue_upgrade():
  ↓
upgrade.py:1191  def continue_upgrade(self):
upgrade.py:1198    self._do_upgrade()
  ↓
upgrade.py:2409  self._upgrade_daemons(to_upgrade, target_image, target_digests)
  ↓
upgrade.py:2043  results = self.mgr.wait_async(self._redeploy_daemons(to_upgrade, target_image))
  ↓
upgrade.py:1892  daemon_spec = service_registry.get_service(svc_type).prepare_create(daemon_spec)
  ↓
cephadmservice.py:621  self.generate_config(daemon_spec)
  ↓
monitoring.py:609  self.mgr.template.render('services/prometheus/prometheus.yml.j2', context)
  ↓
template.py:107  self.engine.render_plain(custom_template, ctx)  ← USES CACHED 7.1 TEMPLATE
  ↓
★ UndefinedError: 'alertmanager_sd_url' is undefined
  ↓
upgrade.py:1907  except Exception as e:
upgrade.py:1908    failures[daemon_spec.name()] = str(e)
  ↓
upgrade.py:2062  if any(failures):
upgrade.py:2070    self._fail_upgrade('UPGRADE_REDEPLOY_DAEMON', {...})
  ↓
OR if the exception propagates higher:
upgrade.py:1207  except Exception as e:
upgrade.py:1208    self._fail_upgrade('UPGRADE_EXCEPTION', {
                     'summary': 'Upgrade: failed due to an unexpected exception',
                     'detail': [f'Unexpected exception occurred during upgrade process: {str(e)}'],
                   })
```

**`_do_upgrade()` catches the exception and calls `_fail_upgrade()` which pauses the upgrade and sets the error state.**

---

## 5. Timeline of Events During Upgrade

```
TIME    EVENT                                       ERROR?
────    ─────                                       ──────
T0      User starts upgrade (CLI or Dashboard)       No
        UpgradeState saved
        ↓
T1      serve() loop iteration
        _check_daemons() runs                       No (deps haven't changed yet)
        continue_upgrade() runs
        _do_upgrade() starts upgrading MGR           No
        MGR failover happens
        ↓
T2      ★ NEW 9.1 MGR IS NOW ACTIVE ★
        New monitoring.py code loaded
        New template.py code loaded
        OLD template still in config-key store
        ↓
T3      serve() loop iteration
        _check_daemons() runs
        Detects Prometheus deps changed              ★ ERROR!
        Tries reconfig → generate_config()
        → render_plain(old_template, new_context)
        → UndefinedError: 'alertmanager_sd_url'
        → Exception CAUGHT AND SWALLOWED             Logged only, continues
        continue_upgrade() runs
        _do_upgrade() upgrades MON daemons           No
        ↓
T4-T10  serve() loop iterations
        _check_daemons() keeps failing for           ★ ERROR every loop
        Prometheus (same error, logged, swallowed)
        _do_upgrade() upgrades crash, osd, mds,      No
        rgw, ceph-exporter...
        ↓
T11     serve() loop iteration (~90% done)
        _check_daemons() fails for Prometheus         ★ ERROR (swallowed again)
        continue_upgrade() runs
        _do_upgrade() reaches PROMETHEUS in order
        Calls _upgrade_daemons() for prometheus
        → _redeploy_daemons_per_host()
        → prepare_create() → generate_config()
        → render_plain(old_template, new_context)
        → UndefinedError: 'alertmanager_sd_url'      ★★★ FATAL ★★★
        → failures['prometheus.xxx'] = str(e)
        → _fail_upgrade('UPGRADE_REDEPLOY_DAEMON')
        → upgrade_state.paused = True
        → upgrade_state.error = "UPGRADE_REDEPLOY_DAEMON: ..."
        ↓
T12     ★ UPGRADE PAUSED AT ~90% ★
        Dashboard polls GET /api/cluster/upgrade/status
        → upgrade_status() returns error message
        → UI shows "Error: UPGRADE_EXCEPTION: ..."
```

---

## 6. Why Dashboard Shows the Error and CLI Appears Not To

### Hypothesis: BOTH paths hit the same error. The difference is in OBSERVABILITY.

#### Dashboard Upgrade:
1. User watches the upgrade progress page in real-time
2. Dashboard polls `GET /api/cluster/upgrade/status` on interval
3. When `upgrade_state.error` is set, the UI immediately shows the error
4. User sees: "UPGRADE_EXCEPTION: Upgrade: failed due to an unexpected exception"
5. Upgrade is paused. User reports "Dashboard upgrade failed at 90%"

#### CLI Upgrade:
1. User runs `ceph orch upgrade start --image <image>` and gets back: "Started upgrade"
2. User may or may not actively watch progress
3. The same error occurs at ~90% when upgrading prometheus
4. Upgrade pauses with the same error state

**What happens next depends on what the CLI user did:**
- If they ran `ceph orch upgrade status` they would see the same error
- If they ran `ceph health detail` they would see `UPGRADE_REDEPLOY_DAEMON` or `UPGRADE_EXCEPTION`
- If someone else (automation, another admin) cleared the config-key and resumed, the CLI user might never know it failed
- If the stale template was already cleared before the CLI upgrade started (e.g., from a previous attempt), it wouldn't fail

### Alternative Hypothesis: CLI upgrade was on a different cluster state

If the CLI upgrade was done on a cluster where:
- The prometheus config-key was never cached (fresh deploy)
- The config-key was already cleared from a previous fix
- The cluster was on a version that didn't cache the template

Then the CLI upgrade would pass cleanly because `template.py:101` would return `None` for the custom_template, and line 109 would render from the on-disk 9.1 `.j2` file.

---

## 7. The Real Bug: Template Not Updated on Upgrade

The actual bug is in `monitoring.py:612-626`:

```python
config_key = 'services/prometheus/prometheus.yml'
existing_config = self.mgr.get_store(config_key)

if existing_config is None:         # ← ONLY writes if not exists
    ...
    self.mgr.set_store(config_key, raw_template)
```

This code:
1. Caches the raw `.j2` template into config-key store the **first time** prometheus is configured
2. **Never updates it** even when the MGR code is upgraded to a new version
3. The new on-disk `.j2` template (9.1) is never used because the old cached template (7.1) takes priority

The `TemplateMgr.render()` in template.py:106-107 always prefers the config-key store version over the on-disk `.j2`:

```python
if custom_template:                              # old 7.1 template found
    return self.engine.render_plain(custom_template, ctx)  # USE OLD
else:
    return self.engine.render(name, ctx)          # never reached
```

---

## 8. UPGRADE_EXCEPTION: How It Gets Raised

There are two possible error IDs depending on where the exception is caught:

### Path 1: `UPGRADE_REDEPLOY_DAEMON` (upgrade.py:2070)
```
_upgrade_daemons() → _redeploy_daemons_per_host()
  → prepare_create() raises exception
  → caught at upgrade.py:1907: failures[daemon_spec.name()] = str(e)
  → checked at upgrade.py:2062: if any(failures):
  → _fail_upgrade('UPGRADE_REDEPLOY_DAEMON', ...)
```

### Path 2: `UPGRADE_EXCEPTION` (upgrade.py:1207-1213)
```
continue_upgrade() → _do_upgrade()
  → any uncaught exception that propagates out of _do_upgrade()
  → caught at upgrade.py:1207: except Exception as e:
  → _fail_upgrade('UPGRADE_EXCEPTION', {
      'summary': 'Upgrade: failed due to an unexpected exception',
      'detail': [f'Unexpected exception occurred during upgrade process: {str(e)}'],
    })
```

In the reported case, the error message was "UPGRADE_EXCEPTION: Upgrade: failed due to an unexpected exception" with "'alertmanager_sd_url' is undefined" in the detail. This means the UndefinedError **propagated past** the `_redeploy_daemons_per_host` catch and was caught by the outer `continue_upgrade()` handler.

Looking at the code flow more carefully, this can happen if the exception occurs during `generate_config()` in the `_do_upgrade()` path BEFORE reaching `_redeploy_daemons_per_host`, or if it occurs in another context within `_do_upgrade()` that doesn't have its own try/except.

---

## 9. Diagram: Full Upgrade Flow

```
                    ┌─────────────┐
                    │   USER      │
                    └──────┬──────┘
                           │
              ┌────────────┴────────────┐
              │                         │
     ┌────────▼────────┐     ┌──────────▼──────────┐
     │   CLI Command    │     │  Dashboard UI        │
     │ ceph orch upgrade│     │ Click "Start Upgrade"│
     │ start --image X  │     │ with custom image    │
     └────────┬─────────┘     └──────────┬───────────┘
              │                          │
     ┌────────▼────────┐     ┌───────────▼──────────────┐
     │ module.py:4779   │     │ Frontend POST             │
     │ upgrade_start()  │     │ /api/cluster/upgrade/start│
     └────────┬─────────┘     └───────────┬──────────────┘
              │                           │
              │                  ┌────────▼─────────┐
              │                  │ cluster.py:66     │
              │                  │ ClusterUpgrade    │
              │                  │  .start()         │
              │                  └────────┬──────────┘
              │                           │
              │                  ┌────────▼─────────────┐
              │                  │ orchestrator.py:187   │
              │                  │ self.api.upgrade_start│
              │                  └────────┬──────────────┘
              │                           │
              └─────────┬─────────────────┘
                        │
               ┌────────▼─────────┐
               │ upgrade.py:913    │
               │ upgrade_start()   │  ← SAME FUNCTION FOR BOTH
               │ Saves UpgradeState│
               │ Returns string    │
               └────────┬──────────┘
                        │
                        │  (returns immediately)
                        │
            ┌───────────▼───────────────────────────────┐
            │         BACKGROUND SERVE LOOP              │
            │         (runs independently)               │
            │                                            │
            │  ┌──────────────────────────────────────┐  │
            │  │  _check_daemons()  (serve.py:137)    │  │
            │  │                                      │  │
            │  │  For each daemon:                    │  │
            │  │    if deps changed:                  │  │
            │  │      action = 'reconfig'             │  │
            │  │      _daemon_action(reconfig)        │  │
            │  │        → prepare_create()            │  │
            │  │          → generate_config()         │  │
            │  │            → template.render()       │  │
            │  │              → get_store(key)        │  │
            │  │              → render_plain(OLD, NEW)│  │
            │  │                                      │  │
            │  │    ★ If exception:                   │  │
            │  │      self.log.exception(e)           │  │
            │  │      # continue...  ← SWALLOWED     │  │
            │  └──────────────────────────────────────┘  │
            │                                            │
            │  ┌──────────────────────────────────────┐  │
            │  │  continue_upgrade()  (serve.py:153)  │  │
            │  │    → _do_upgrade()                   │  │
            │  │      for daemon_type in ORDER:       │  │
            │  │        ... upgrade mgr, mon, osd ... │  │
            │  │        ... reaches prometheus ...     │  │
            │  │        _upgrade_daemons()             │  │
            │  │          → _redeploy_daemons_per_host │  │
            │  │            → prepare_create()         │  │
            │  │              → generate_config()      │  │
            │  │                → template.render()    │  │
            │  │                  → render_plain(OLD)  │  │
            │  │                                       │  │
            │  │    ★ If exception:                    │  │
            │  │      _fail_upgrade(UPGRADE_EXCEPTION) │  │
            │  │        → upgrade_state.error = ...    │  │
            │  │        → upgrade_state.paused = True  │  │
            │  │        → health_check set             │  │
            │  │      ★★★ UPGRADE STOPS ★★★           │  │
            │  └──────────────────────────────────────┘  │
            └────────────────────────────────────────────┘
```

---

## 10. Conclusion

### The Root Cause
A stale Prometheus Jinja2 template cached in the ceph config-key store at key `services/prometheus/prometheus.yml` (full MON key: `mgr/cephadm/services/prometheus/prometheus.yml`). This template was written by the 7.1 version of monitoring.py and uses variables (`alertmanager_sd_url`, `node_exporter_sd_url`, etc.) that no longer exist in the 9.1 context dictionary (replaced by `service_discovery_cfg`). The `monitoring.py:612-626` code never updates the cached template — it only writes if the key doesn't exist yet.

### Why the Upgrade Fails at ~90%
MGR upgrades first (position 0). Prometheus upgrades near the end (position 14). After MGR upgrades to 9.1 at ~T2, the new `generate_config()` code runs with the new context format, but the old template is still cached. Every serve loop, `_check_daemons()` tries to reconfig prometheus and fails — but this error is silently swallowed (serve.py:1596-1601). When `_do_upgrade()` finally reaches the prometheus daemon type at ~90%, `_upgrade_daemons()` → `prepare_create()` → `generate_config()` hits the same error, but THIS time the exception propagates to `_fail_upgrade()`, which pauses the upgrade and sets `upgrade_state.error`.

### Why CLI "Passed"
It didn't. Either:
1. The stale config-key template was already cleared/never existed on the CLI-tested cluster
2. The CLI upgrade hit the same error, was fixed and resumed, and the person who ran it didn't report the intermediate failure
3. On a fresh cluster (no prior prometheus config), the template is written for the first time by 9.1 code, so it matches

### The Real Bug
`monitoring.py:618` — `if existing_config is None:` — should also check if the cached template is from a different ceph version, or the upgrade process should clear/update stale cached templates before proceeding. The config-key store acts as a "write-once" cache with no invalidation strategy across version upgrades.

### Fix
```bash
ceph config-key rm mgr/cephadm/services/prometheus/prometheus.yml
```
Then resume the upgrade. The next `generate_config()` call will find no cached template, use the on-disk 9.1 `.j2`, and re-cache it.

---

## 11. Dashboard Unresponsiveness After 7.1→9.1 Upgrade Failure

### Symptom
After the upgrade fails at 90% on 7.1→9.1, the dashboard becomes unresponsive — navigation stops working. For 8.1→9.1 the dashboard works fine.

### Why 8.1 Doesn't Hit This
The 8.1 prometheus template already uses `service_discovery_cfg` format (or a compatible intermediate). No template mismatch → no `_check_daemons` failures → upgrade completes cleanly → no error state → dashboard stays responsive.

### Root Cause: `upgradeStatus$` Observable Error Kills the UI

The dashboard has **two upgrade components** that create `upgradeStatus$` observables:

#### upgrade.component.ts:59-62 (main upgrade page)
```typescript
this.upgradeStatus$ = this.subject.pipe(
  switchMap(() => this.upgradeService.status()),   // ← NO catchError!
  shareReplay(1)
);
```

#### upgrade-progress.component.ts:49-57 (progress page)
```typescript
this.upgradeStatus$ = this.subject.pipe(
  switchMap(() => this.upgradeService.status()),   // ← NO catchError!
  tap((status) => {
    if (!status.in_progress) {
      this.router.navigate(['/upgrade']);
    }
  }),
  shareReplay(1)
);
```

**Both lack `catchError`.**

### The Failure Chain

```
  _check_daemons() fails on prometheus every loop
    ↓
  Template error floods MGR logs (self.log.exception(e) per loop)
    ↓
  _check_daemons takes longer (handling exceptions for each prometheus daemon)
    ↓
  serve loop slows down
    ↓
  Dashboard API calls (/api/summary, /api/cluster/upgrade/status) slow or timeout
    ↓
  HTTP error propagates to upgradeStatus$ observable
    ↓
  switchMap() has NO catchError → error propagates to shareReplay(1)
    ↓
  shareReplay(1) CACHES the error
    ↓
  Every subscriber to upgradeStatus$ immediately gets the cached error
    ↓
  Template `*ngIf="upgradeStatus$ | async as status"` fails silently
    ↓
  The entire <ng-container> block (wrapping all navigation cards) doesn't render
    ↓
  OR: async pipe error kills change detection for the component
    ↓
  Navigation appears frozen
```

### Contributing Factors

#### 1. SummaryService Has No Error Handler (summary.service.ts:24-27)
```typescript
startPolling(): Subscription {
  return this.timerService
    .get(() => this.retrieveSummaryObservable(), this.REFRESH_INTERVAL)
    .subscribe(this.retrieveSummaryObserver());
    // retrieveSummaryObserver() returns ONLY a next handler:
    // (data) => { this.summaryDataSource.next(data); }
    // NO error handler! NO complete handler!
}
```

When `GET /api/summary` fails (e.g., MGR slow due to _check_daemons loop):
- The error terminates the `timerService` subscription
- `summaryData$` stops updating
- All components subscribed to `summaryService.subscribe()` freeze with stale data
- `version`, `executingTasks` never update again

#### 2. ApiInterceptorService Always Re-throws (api-interceptor.service.ts:145)
```typescript
// Line 145 - ALWAYS re-throws
return observableThrowError(resp);
```

The HTTP interceptor shows a notification but **always re-throws the error**. If the upstream observable doesn't catch it, the subscription dies.

#### 3. ModuleStatusGuardService Blocks Navigation (module-status-guard.service.ts:74)
```typescript
// The upgrade route has this guard (app-routing.module.ts:329):
canActivate: [ModuleStatusGuardService]

// The guard makes an HTTP call:
return this.http.get(`ui-api/orchestrator/status`).pipe(
  map((resp) => {
    if (!resp.available && !backendCheck) {
      this.router.navigate([config.redirectTo]);  // redirects to /error
    }
    return resp.available;
  }),
  catchError(() => {
    this.router.navigate([config.redirectTo]);  // redirects to /error
    return observableOf(false);
  })
);
```

If `ui-api/orchestrator/status` times out because the MGR is slow from _check_daemons failures:
- The guard either returns `false` (blocking the route)
- Or redirects to `/error` page
- Either way, navigating AWAY from upgrade and BACK is blocked

#### 4. Subscription Leak in upgrade-progress.component.ts:63-67
```typescript
// Line 63 - subscription created but NEVER stored or unsubscribed
this.summaryService.subscribe((summary) => {
  this.executingTask = summary.executing_tasks.filter(...)
});

// Line 137 - ngOnDestroy only unsubscribes interval, not the summary sub
ngOnDestroy() {
  this.interval?.unsubscribe();   // ← missing summaryService unsub!
}
```

If user navigates away and back, subscriptions accumulate. Each leaked subscription holds references that prevent garbage collection.

### Diagram: Dashboard Freeze Flow

```
┌─────────────────────────────────────────────────────┐
│           BACKEND (after upgrade paused at 90%)      │
│                                                      │
│  serve() loop runs continuously:                     │
│  ┌─────────────────────────────────────────────────┐ │
│  │ _check_daemons()                                │ │
│  │   → For EACH prometheus daemon:                 │ │
│  │     → _daemon_action(reconfig)                  │ │
│  │       → prepare_create()                        │ │
│  │         → generate_config()                     │ │
│  │           → template.render()                   │ │
│  │             → UndefinedError ← EVERY LOOP       │ │
│  │     → self.log.exception(e) ← LOG FLOODING     │ │
│  │     → continue (swallowed)                      │ │
│  │                                                 │ │
│  │ continue_upgrade()                              │ │
│  │   → upgrade_state.paused == True → return False │ │
│  │     (does nothing, upgrade is paused)           │ │
│  └─────────────────────────────────────────────────┘ │
│                                                      │
│  Result: serve loop slower, API responses delayed    │
└───────────────────────┬─────────────────────────────┘
                        │
                        │ HTTP responses slow/timeout
                        ▼
┌─────────────────────────────────────────────────────┐
│           FRONTEND (Angular app in browser)          │
│                                                      │
│  ┌─────────────────────────────────────────────────┐ │
│  │ RefreshIntervalService                          │ │
│  │   emits tick every 5s                           │ │
│  │     ↓                                           │ │
│  │ upgradeStatus$ = subject.pipe(                  │ │
│  │   switchMap(() => upgradeService.status()),      │ │
│  │   // ← status() HTTP call fails/times out       │ │
│  │   // ← NO catchError in pipe                    │ │
│  │   shareReplay(1)                                │ │
│  │   // ← ERROR CACHED in replay buffer            │ │
│  │ )                                               │ │
│  │     ↓                                           │ │
│  │ Template: *ngIf="upgradeStatus$ | async as st"  │ │
│  │   → async pipe receives error                   │ │
│  │   → ng-container doesn't render                 │ │
│  │   → UI cards (New Version, Status) vanish       │ │
│  └─────────────────────────────────────────────────┘ │
│                                                      │
│  ┌─────────────────────────────────────────────────┐ │
│  │ SummaryService                                  │ │
│  │   GET /api/summary fails                        │ │
│  │   → No error handler in subscribe()             │ │
│  │   → timerService subscription TERMINATES        │ │
│  │   → summaryData$ STOPS EMITTING                 │ │
│  │   → All components using summaryService FREEZE  │ │
│  │   → Sidebar navigation data stale               │ │
│  └─────────────────────────────────────────────────┘ │
│                                                      │
│  ┌─────────────────────────────────────────────────┐ │
│  │ ModuleStatusGuardService                        │ │
│  │   GET /ui-api/orchestrator/status times out     │ │
│  │   → guard returns false OR redirects to /error  │ │
│  │   → user CAN'T navigate to /upgrade or back     │ │
│  │   → clicking sidebar items blocked by guard     │ │
│  └─────────────────────────────────────────────────┘ │
│                                                      │
│  Result: Dashboard appears completely frozen         │
└─────────────────────────────────────────────────────┘
```

### Why 7.1→9.1 Hits This But 8.1→9.1 Doesn't

| Factor | 7.1→9.1 | 8.1→9.1 |
|--------|---------|---------|
| Stale template in config-key | YES (7.1 format) | NO (8.1 already compatible) |
| _check_daemons fails every loop | YES | NO |
| Serve loop slowed by exceptions | YES | NO |
| API calls slow/timeout | YES | NO |
| upgradeStatus$ caches error | YES | NO |
| SummaryService subscription dies | YES | NO |
| Dashboard freezes | YES | NO |

The 8.1→9.1 upgrade never creates the error condition in the first place because the prometheus template format is already compatible with the 9.1 context. No template mismatch → no _check_daemons failures → serve loop runs at normal speed → API calls respond normally → no cached errors in observables → dashboard stays responsive.

### Summary of Frontend Bugs (independent of the upgrade issue)

These bugs exist in the code and can be triggered by ANY backend error, not just this upgrade scenario:

1. **upgrade.component.ts:59-62** — `upgradeStatus$` has no `catchError`, `shareReplay(1)` caches errors permanently
2. **upgrade-progress.component.ts:49-57** — Same issue
3. **summary.service.ts:24-27** — No error handler on polling subscription, one error kills all polling
4. **upgrade-progress.component.ts:63-67** — Subscription leak, `summaryService.subscribe()` never unsubscribed

---

## 12. Multi-Cluster Token KeyError During 7.X→8.X Upgrade

### Symptom
During upgrade from version 7 to 8, Dashboard crashes with:
```
Jun 18 15:54:30 ceph-vpap-i71z10-o3i84a-node1-installer ceph-mgr[66066]: [dashboard ERROR exception] Internal Server Error
Traceback (most recent call last):
  File "/usr/share/ceph/mgr/dashboard/services/exception.py", line 47, in dashboard_exception_handler
    return handler(*args, **kwargs)
  File "/lib/python3.9/site-packages/cherrypy/_cpdispatch.py", line 54, in __call__
    return self.callable(*self.args, **self.kwargs)
  File "/usr/share/ceph/mgr/dashboard/controllers/_base_controller.py", line 264, in inner
    ret = func(*args, **kwargs)
  File "/usr/share/ceph/mgr/dashboard/controllers/multi_cluster.py", line 436, in check_token_status
    return self.check_token_status_array()
  File "/usr/share/ceph/mgr/dashboard/controllers/multi_cluster.py", line 421, in check_token_status_array
    token = config[0]['token']
KeyError: 'token'
```

### Root Cause
**multi_cluster.py:414-431** — `check_token_status_array()` assumes all multi-cluster configs have a specific structure with `config[0]['token']`, `config[0]['name']`, and `config[0]['user']` keys, but does NOT validate this structure before accessing it.

```python
# multi_cluster.py:414-431
def check_token_status_array(self):
    token_status_map = {}
    multi_cluster_config = self.load_multi_cluster_config()

    if 'config' in multi_cluster_config:
        for _, config in multi_cluster_config['config'].items():
            cluster_name = config[0]['name']      # ← NO VALIDATION
            token = config[0]['token']            # ← KeyError HERE
            user = config[0]['user']              # ← Could also fail
            status = self.check_token_status_expiration(token)
            time_left = self.get_time_left(token)
            token_status_map[cluster_name] = {
                'status': status,
                'user': user,
                'time_left': time_left
            }

    return token_status_map
```

### What Happens During Upgrade

1. **Before upgrade (v7)**: Multi-cluster config is stored in `Settings.MULTICLUSTER_CONFIG`
2. **MGR upgrades to v8**: New MGR code loads with potentially different multi-cluster config schema expectations
3. **Dashboard API called**: Frontend or background poll calls `GET /api/multi-cluster/check_token_status`
4. **Config structure mismatch**: 
   - Old config (v7) may have incomplete/different structure
   - New code (v8) expects `config[0]` to be a dict with `['token', 'name', 'user']` keys
   - `config[0]` exists but is missing the `'token'` key (or is an empty dict, or has different structure)
5. **Unhandled KeyError**: Line 421 crashes the entire request
6. **Dashboard becomes unstable**: This endpoint may be polled frequently, flooding logs with exceptions

### Why This Happens During Upgrade Specifically

During the upgrade:
- Multi-cluster config is persisted in the MON config-key store (similar to the prometheus template issue)
- The v7 config schema may differ from v8's expectations
- Unlike prometheus templates which have version-specific `.j2` files, the multi-cluster config is JSON data with no schema migration logic
- The code blindly assumes the structure without defensive checks

### Potential Config Structure Variations

**Expected structure (v8):**
```python
{
    'config': {
        'cluster1': [
            {
                'name': 'cluster1',
                'token': 'abc123...',
                'user': 'admin',
                ...
            }
        ],
        ...
    }
}
```

**Possible v7 structure causing the issue:**
```python
{
    'config': {
        'cluster1': [
            {
                'name': 'cluster1',
                # 'token' key missing or renamed
                'auth_token': 'abc123...',  # different key name?
                'user': 'admin'
            }
        ]
    }
}
```

Or:
```python
{
    'config': {
        'cluster1': [{}]  # empty dict
    }
}
```

Or:
```python
{
    'config': {
        'cluster1': []  # empty array → config[0] IndexError
    }
}
```

### The Bug

**No validation or defensive coding:**
1. No check if `config` is a non-empty array before accessing `config[0]`
2. No check if `config[0]` has required keys before accessing them
3. No try/except around key access
4. No schema migration logic when loading old configs
5. No graceful degradation (should skip invalid configs, not crash entire request)

### Fix Strategy

**Option 1: Defensive key access**
```python
def check_token_status_array(self):
    token_status_map = {}
    multi_cluster_config = self.load_multi_cluster_config()

    if 'config' in multi_cluster_config:
        for cluster_alias, config in multi_cluster_config['config'].items():
            # Validate structure
            if not config or not isinstance(config, list) or len(config) == 0:
                logger.warning(f"Skipping invalid multi-cluster config for {cluster_alias}: empty or invalid structure")
                continue
            
            cluster_config = config[0]
            
            # Validate required keys
            if not all(k in cluster_config for k in ['name', 'token', 'user']):
                logger.warning(f"Skipping multi-cluster config for {cluster_alias}: missing required keys (name, token, or user)")
                continue
            
            cluster_name = cluster_config['name']
            token = cluster_config['token']
            user = cluster_config['user']
            
            try:
                status = self.check_token_status_expiration(token)
                time_left = self.get_time_left(token)
                token_status_map[cluster_name] = {
                    'status': status,
                    'user': user,
                    'time_left': time_left
                }
            except Exception as e:
                logger.exception(f"Failed to check token status for {cluster_name}: {e}")
                continue

    return token_status_map
```

**Option 2: Schema migration in `load_multi_cluster_config()`**
Add migration logic to convert v7 configs to v8 format when loading.

**Option 3: Clear stale config on upgrade**
Similar to the prometheus template fix — detect version mismatch and clear/reset multi-cluster config.

### Impact

- **Severity**: HIGH during upgrade window
- **Blast radius**: All Dashboard API endpoints may fail if `check_token_status` is called in a global interceptor or app initialization
- **User experience**: Dashboard completely broken during upgrade, error flooding logs
- **Workaround**: Clear multi-cluster config manually:
  ```bash
  ceph config-key rm mgr/dashboard/MULTICLUSTER_CONFIG
  ```
  Or restart MGR to reset Settings.

### Related Issues

This is the SAME root cause pattern as Issue #11 (prometheus template):
1. **Persistent config stored in MON config-key store**
2. **No version tracking or schema validation**
3. **No migration logic on upgrade**
4. **Code assumes current-version structure without defensive checks**
5. **Upgrade breaks when old data meets new code**

Both issues demonstrate a **systemic gap in upgrade handling for persisted configuration data**.
