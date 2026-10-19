# VIOS live acceptance

This is a scrubbed summary of two end-to-end PTxray runs on a live Virtual I/O Server. The host name, serial numbers, addresses, and the reports themselves are not published.

## Test system

- A loaned, bare VIOS: `ioslevel` 4.1.2.00, AIX 7300-04-00-2546, POWER10.
- No Shared Ethernet Adapter (SEA), NPIV, virtual SCSI, Shared Storage Pool (SSP), or vNIC was configured.
- The VIOS had no TCP/IP configured, so it was reached through the HMC console.

## Run 1: PTxray 1.8.2, 2026-09-27

- Command: `ksh ptxray-vios.sh` from the extracted AIX report bundle, read-only, with `--definitions-bundle` (definitions staged on the host). Exit status 0.
- 578 findings: 290 PASS, 196 FAIL, 57 N/A, 21 WARN, 14 NOT_ASSESSED.
- 17 VIOS-specific findings were checked live. `rmc_state` was NOT_ASSESSED and `rootvg_mirror` was WARN.

## Run 2: PTxray 1.8.4, 2026-09-28

- 611 rows: 291 PASS, 225 FAIL, 60 N/A, 21 WARN, 14 NOT ASSESSED.
- `vios_level`, `vios_backup_schedule`, `vios_users_nonpadmin`, and `vios_users_shell_bypass` passed. The report recorded VIOS 4.1.2.00 on the supported 4.1 line.
- Every SEA, NPIV, virtual SCSI, SSP, and vNIC check (`sea_failover`, `sea_largesend`, `sea_threading`, `npiv_maps`, `npiv_redundancy`, `vscsi_maps`, `vscsi_lv_backing`, `vscsi_reserve`, `ssp_cluster`, `ssp_alert_threshold`, `ssp_node_upgrade`, `ssp_pool_capacity`, `vnic_maps`) and `vios_topology` reported not applicable (N/A), because none of those features was configured.
- `rootvg_mirror`, `viosecure_level`, and `viosecure_firewall` were WARN. `rmc_state` was NOT ASSESSED.

## What this shows and what it does not

- `ptxray-vios.sh` runs end to end on a live VIOS 4.1.2.00 with PTxray 1.8.2 and 1.8.4, read-only, and produces a complete report.
- The checks for configured SEA, NPIV, virtual SCSI, and SSP were verified live only in the not-present case. They have not been run against a live VIOS that has those features configured. Their configured branches are still covered only by fixtures (see RELEASE-NOTES v1.8.3).
- Only VIOS 4.1 (4.1.2.00) was tested. Other VIOS levels have not been run live.
- PASS, FAIL, and WARN counts describe this one test system's configuration. They are not a benchmark of PTxray.
