/**
 * DHCPd-Guard Frontend Application
 * Dashboard ↔ Backend ↔ State-Aware DHCP Engine
 */

"use strict";

let ipDonutChartInstance = null;
let activityChartInstance = null;
let attackDonutChartInstance = null;

let allLeasesData = [];
let allEventsData = [];
let allRulesData = [];

let currentSelectedLeaseId = null;
let currentSelectedLeaseData = null;


// ============================================================
// INITIALIZATION
// ============================================================

document.addEventListener("DOMContentLoaded", () => {
  initLiveClock();
  setupLogoutButton();
  checkAuthentication();
  setupClickOutside();
  addDhcpTransactionButton();
});


// ============================================================
// LIVE CLOCK
// ============================================================

function initLiveClock() {
  const clockEl =
    document.getElementById("clock-display");

  function updateClock() {
    const now = new Date();

    let hours = now.getHours();
    const minutes =
      String(now.getMinutes()).padStart(2, "0");

    const ampm =
      hours >= 12 ? "PM" : "AM";

    hours = hours % 12;
    hours = hours || 12;

    const months = [
      "Jan", "Feb", "Mar", "Apr",
      "May", "Jun", "Jul", "Aug",
      "Sep", "Oct", "Nov", "Dec"
    ];

    const timeStr =
      `${hours}:${minutes} ${ampm}`;

    const dateStr =
      `${months[now.getMonth()]} ${now.getDate()}, ${now.getFullYear()}`;

    if (clockEl) {
      clockEl.innerHTML = `
        <span class="time-part">${timeStr}</span>
        <span class="date-part">${dateStr}</span>
      `;
    }
  }

  updateClock();
  setInterval(updateClock, 10000);
}


// ============================================================
// AUTHENTICATION
// ============================================================

async function checkAuthentication() {
  try {
    const response = await fetch("/api/auth/me");
    if (!response.ok) {
      window.location.href = "/";
      return;
    }
    const user = await response.json();
    const userEl = document.querySelector(".user-name");
    if (userEl) userEl.textContent = user.user || "admin";
    fetchInitialData();
    setupSSE();
  } catch (_) {
    window.location.href = "/";
  }
}

function setupLogoutButton() {
  const target = document.querySelector(".user-info") || document.querySelector("header");
  if (!target || document.getElementById("logout-btn")) return;
  const button = document.createElement("button");
  button.id = "logout-btn";
  button.textContent = "Logout";
  button.style.cssText = "margin-left:12px;padding:7px 12px;border:1px solid #dbe3ef;border-radius:8px;background:#fff;cursor:pointer;font-weight:600;color:#334155;";
  button.onclick = async () => {
    await fetch("/api/auth/logout", { method: "POST" });
    window.location.href = "/";
  };
  target.appendChild(button);
}

// ============================================================
// INITIAL DATA
// ============================================================

async function fetchInitialData() {
  try {
    const [
      stats,
      leases,
      events,
      activity,
      attacks,
      rules,
      clients
    ] = await Promise.all([
      fetch("/api/stats").then(r => r.json()),
      fetch("/api/leases").then(r => r.json()),
      fetch("/api/events").then(r => r.json()),
      fetch("/api/activity").then(r => r.json()),
      fetch("/api/attacks").then(r => r.json()),
      fetch("/api/rules").then(r => r.json()),
      fetch("/api/clients").then(r => r.json())
    ]);

    allLeasesData =
      Array.isArray(leases)
        ? leases
        : (leases.leases || []);

    allEventsData =
      Array.isArray(events)
        ? events
        : (events.events || []);

    allRulesData =
      Array.isArray(rules)
        ? rules
        : (rules.rules || []);

    updateStatsUI(stats);

    renderCharts(
      stats,
      activity,
      attacks
    );

    renderLeasesTable(
      allLeasesData
    );

    renderEventsTimeline(
      allEventsData
    );

    renderSecurityRules(
      allRulesData
    );

    renderClientStates(
      clients
    );

  } catch (error) {
    console.error(
      "Dashboard loading error:",
      error
    );

    showToast(
      "Failed to load dashboard data.",
      "danger"
    );
  }
}


// ============================================================
// REFRESH DASHBOARD
// ============================================================

async function refreshDashboard() {
  try {
    const [
      stats,
      leases,
      events,
      attacks,
      rules,
      clients
    ] = await Promise.all([
      fetch("/api/stats").then(r => r.json()),
      fetch("/api/leases").then(r => r.json()),
      fetch("/api/events").then(r => r.json()),
      fetch("/api/attacks").then(r => r.json()),
      fetch("/api/rules").then(r => r.json()),
      fetch("/api/clients").then(r => r.json())
    ]);

    allLeasesData =
      Array.isArray(leases)
        ? leases
        : (leases.leases || []);

    allEventsData =
      Array.isArray(events)
        ? events
        : (events.events || []);

    allRulesData =
      Array.isArray(rules)
        ? rules
        : (rules.rules || []);

    updateStatsUI(stats);

    renderLeasesTable(
      allLeasesData
    );

    renderEventsTimeline(
      allEventsData
    );

    renderSecurityRules(
      allRulesData
    );

    renderClientStates(
      clients
    );

    updateDonutCharts(
      stats,
      attacks
    );

  } catch (error) {
    console.error(
      "Dashboard refresh failed:",
      error
    );
  }
}


// ============================================================
// STATISTICS
// ============================================================

function updateStatsUI(stats) {
  if (!stats) return;

  setText(
    "stat-total-ip",
    stats.totalIpPool
  );

  setText(
    "stat-pool-range",
    `(${stats.poolRangeStr})`
  );

  setText(
    "stat-active-leases",
    stats.activeLeasesCount
  );

  setText(
    "stat-active-percent",
    `(${stats.activeLeasesPercent}% used)`
  );

  setText(
    "stat-available-ips",
    stats.availableIpsCount
  );

  setText(
    "stat-available-percent",
    `(${stats.availableIpsPercent}% free)`
  );

  setText(
    "stat-blocked-attacks",
    stats.blockedAttacksCount
  );


  // Pool donut
  setText(
    "donut-usage-percent",
    `${stats.activeLeasesPercent}%`
  );

  setText(
    "legend-active-leases",
    stats.activeLeasesCount
  );

  setText(
    "legend-available-leases",
    stats.availableIpsCount
  );

  setText(
    "legend-total-ips",
    stats.totalIpPool
  );


  // Attack donut
  if (stats.attacksBreakdown) {
    setText(
      "donut-attack-total",
      stats.attacksBreakdown.total
    );

    setText(
      "legend-starvation-attacks",
      stats.attacksBreakdown.starvation
    );

    setText(
      "legend-rogue-attacks",
      stats.attacksBreakdown.rogue
    );

    setText(
      "legend-other-attacks",
      stats.attacksBreakdown.other
    );
  }


  // Bottom pool widget
  setText(
    "bottom-pool-range-num",
    stats.poolRangeStr
  );

  const usedBar =
    document.getElementById(
      "progress-bar-used"
    );

  const freeBar =
    document.getElementById(
      "progress-bar-free"
    );

  if (usedBar) {
    usedBar.style.width =
      `${stats.activeLeasesPercent}%`;
  }

  if (freeBar) {
    freeBar.style.width =
      `${stats.availableIpsPercent}%`;
  }

  setText(
    "bottom-used-count",
    stats.activeLeasesCount
  );

  setText(
    "bottom-free-count",
    stats.availableIpsCount
  );


  // All lease modal count
  setText(
    "all-leases-count",
    stats.activeLeasesCount
  );
}


// ============================================================
// CHARTS
// ============================================================

function renderCharts(
  stats,
  activity,
  attacks
) {
  if (
    typeof Chart === "undefined"
  ) {
    console.warn(
      "Chart.js not available."
    );

    return;
  }


  // ----------------------------------------------------------
  // IP POOL DONUT
  // ----------------------------------------------------------

  const ipCanvas =
    document.getElementById(
      "ipPoolDonutChart"
    );

  if (ipCanvas) {
    if (ipDonutChartInstance) {
      ipDonutChartInstance.destroy();
    }

    ipDonutChartInstance =
      new Chart(ipCanvas, {
        type: "doughnut",

        data: {
          labels: [
            "Active Leases",
            "Available"
          ],

          datasets: [{
            data: [
              stats.activeLeasesCount,
              stats.availableIpsCount
            ],

            backgroundColor: [
              "#10b981",
              "#cbd5e1"
            ],

            borderWidth: 0
          }]
        },

        options: {
          responsive: true,
          maintainAspectRatio: false,

          cutout: "74%",

          plugins: {
            legend: {
              display: false
            }
          }
        }
      });
  }


  // ----------------------------------------------------------
  // NETWORK ACTIVITY
  // ----------------------------------------------------------

  const activityCanvas =
    document.getElementById(
      "networkActivityChart"
    );

  if (
    activityCanvas &&
    activity &&
    activity.labels &&
    activity.datasets
  ) {
    if (activityChartInstance) {
      activityChartInstance.destroy();
    }

    activityChartInstance =
      new Chart(activityCanvas, {
        type: "line",

        data: {
          labels: activity.labels,

          datasets: [{
            label: "DHCP Requests",

            data:
              activity.datasets[0]?.data || [],

            borderColor: "#2563eb",

            borderWidth: 2,

            backgroundColor:
              "rgba(37,99,235,0.12)",

            fill: true,

            tension: 0.4,

            pointRadius: 2
          }]
        },

        options: {
          responsive: true,
          maintainAspectRatio: false,

          plugins: {
            legend: {
              display: false
            }
          },

          scales: {
            y: {
              beginAtZero: true
            }
          }
        }
      });
  }


  // ----------------------------------------------------------
  // ATTACK DONUT
  // ----------------------------------------------------------

  const attackCanvas =
    document.getElementById(
      "attackDonutChart"
    );

  if (attackCanvas && attacks) {
    if (attackDonutChartInstance) {
      attackDonutChartInstance.destroy();
    }

    attackDonutChartInstance =
      new Chart(attackCanvas, {
        type: "doughnut",

        data: {
          labels: [
            "Starvation Attack",
            "Rogue DHCP",
            "Other"
          ],

          datasets: [{
            data: [
              attacks.starvation || 0,
              attacks.rogue || 0,
              attacks.other || 0
            ],

            backgroundColor: [
              "#ef4444",
              "#f97316",
              "#cbd5e1"
            ],

            borderWidth: 0
          }]
        },

        options: {
          responsive: true,
          maintainAspectRatio: false,

          cutout: "74%",

          plugins: {
            legend: {
              display: false
            }
          }
        }
      });
  }
}


// ============================================================
// UPDATE CHARTS
// ============================================================

function updateDonutCharts(
  stats,
  attacks
) {
  if (ipDonutChartInstance) {
    ipDonutChartInstance.data
      .datasets[0]
      .data = [
        stats.activeLeasesCount,
        stats.availableIpsCount
      ];

    ipDonutChartInstance.update();
  }


  if (
    attackDonutChartInstance &&
    attacks
  ) {
    attackDonutChartInstance.data
      .datasets[0]
      .data = [
        attacks.starvation || 0,
        attacks.rogue || 0,
        attacks.other || 0
      ];

    attackDonutChartInstance.update();
  }
}


// ============================================================
// ACTIVE LEASE TABLE
// ============================================================

function renderLeasesTable(
  leases
) {
  const tbody =
    document.getElementById(
      "leases-tbody"
    );

  const allTbody =
    document.getElementById(
      "all-leases-tbody"
    );

  if (!tbody) return;

  tbody.innerHTML = "";

  if (allTbody) {
    allTbody.innerHTML = "";
  }


  // Main dashboard: first 5
  leases
    .slice(0, 5)
    .forEach((lease, index) => {
      tbody.appendChild(
        createLeaseRow(
          lease,
          index + 1
        )
      );
    });


  // All leases modal
  if (allTbody) {
    leases.forEach(
      (lease, index) => {
        allTbody.appendChild(
          createLeaseRow(
            lease,
            index + 1,
            true
          )
        );
      }
    );
  }


  // Empty state
  if (leases.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7"
            style="text-align:center;padding:25px;">
          No active DHCP leases
        </td>
      </tr>
    `;

    if (allTbody) {
      allTbody.innerHTML = `
        <tr>
          <td colspan="7"
              style="text-align:center;padding:25px;">
            No active DHCP leases
          </td>
        </tr>
      `;
    }
  }
}


// ============================================================
// CREATE LEASE ROW
// ============================================================

function createLeaseRow(
  lease,
  displayNum
) {
  const tr =
    document.createElement("tr");

  tr.innerHTML = `
    <td>${displayNum}</td>

    <td class="mono-text">
      <strong>
        ${escapeHtml(lease.ip)}
      </strong>
    </td>

    <td class="mono-text">
      ${escapeHtml(lease.mac)}
    </td>

    <td>
      ${escapeHtml(
        lease.deviceType ||
        "DHCP Client"
      )}
    </td>

    <td>
      ${escapeHtml(
        lease.leaseTimeLeft ||
        "2h 00m"
      )}
    </td>

    <td>
      <span class="status-badge-inline active">
        ${escapeHtml(
          lease.status ||
          "Active"
        )}
      </span>
    </td>

    <td>
      <button
        class="table-action-btn"
        title="Lease Actions"
        onclick="openRowMenu(event, ${lease.id})">
        &#8942;
      </button>
    </td>
  `;

  return tr;
}


// ============================================================
// EVENTS TIMELINE
// ============================================================

function renderEventsTimeline(
  events
) {
  const container =
    document.getElementById(
      "events-timeline-list"
    );

  const fullContainer =
    document.getElementById(
      "full-logs-container"
    );

  if (container) {
    container.innerHTML = "";

    events
      .slice(0, 5)
      .forEach(event => {
        container.appendChild(
          createEventRow(event)
        );
      });

    if (events.length === 0) {
      container.innerHTML = `
        <div style="
          padding:20px;
          text-align:center;
          color:#64748b;">
          No recent events
        </div>
      `;
    }
  }


  renderFullLogs(
    events,
    fullContainer
  );
}


// ============================================================
// EVENT ROW
// ============================================================

function createEventRow(
  event
) {
  const row =
    document.createElement("div");

  row.className =
    "event-row";

  let bullet =
    "green";

  const type =
    String(
      event.type || ""
    ).toLowerCase();

  const status =
    String(
      event.status || ""
    ).toLowerCase();

  if (
    type === "danger" ||
    type === "attack" ||
    status === "blocked"
  ) {
    bullet = "red";
  } else if (
    type === "warning" ||
    status === "expired"
  ) {
    bullet = "slate";
  }

  const title =
    event.title ||
    event.message ||
    "DHCP Event";

  const detail =
    event.detail ||
    event.message ||
    "";

  row.innerHTML = `
    <span class="event-time">
      ${escapeHtml(
        event.time || ""
      )}
    </span>

    <div class="event-bullet-wrapper">
      <span class="event-bullet ${bullet}">
      </span>
    </div>

    <div class="event-info">
      <span class="event-title">
        ${escapeHtml(title)}
      </span>

      <span class="event-detail">
        ${escapeHtml(detail)}
      </span>
    </div>
  `;

  return row;
}


// ============================================================
// FULL LOGS
// ============================================================

function renderFullLogs(
  events,
  container
) {
  if (!container) return;

  container.innerHTML = "";

  events.forEach(event => {
    const log =
      document.createElement("div");

    log.className =
      `log-entry ${event.type || ""}`;

    const title =
      event.title ||
      event.message ||
      "DHCP Event";

    const detail =
      event.detail ||
      event.message ||
      "";

    const status =
      event.status ||
      event.type ||
      "info";

    log.innerHTML = `
      <div>
        <strong>
          [${escapeHtml(
            event.time || ""
          )}]
        </strong>

        ${escapeHtml(title)}

        <span style="color:#64748b;">
          — ${escapeHtml(detail)}
        </span>
      </div>

      <span style="
        text-transform:uppercase;
        font-size:10px;
        font-weight:700;">
        ${escapeHtml(status)}
      </span>
    `;

    container.appendChild(log);
  });
}


// ============================================================
// SECURITY RULES
// ============================================================

function renderSecurityRules(
  rules
) {
  const container =
    document.getElementById(
      "rules-container"
    );

  if (!container) return;

  container.innerHTML = "";

  if (!rules.length) {
    container.innerHTML = `
      <div style="
        padding:20px;
        text-align:center;
        color:#64748b;">
        No security rules configured.
      </div>
    `;

    return;
  }

  rules.forEach(rule => {
    const div =
      document.createElement("div");

    div.className =
      "rule-item";

    const active =
      rule.status === "Active";

    div.innerHTML = `
      <div class="rule-info">
        <strong>
          ${escapeHtml(rule.name)}
        </strong>

        <p>
          ${escapeHtml(
            rule.description
          )}
        </p>
      </div>

      <label class="switch">

        <input
          type="checkbox"
          ${active ? "checked" : ""}
          onchange="
            toggleRule(
              ${rule.id},
              this.checked
            )
          "
        >

        <span class="slider"></span>

      </label>
    `;

    container.appendChild(div);
  });
}


// ============================================================
// CLIENT STATE TRACKING
// ============================================================

function renderClientStates(
  clients
) {
  const container =
    document.getElementById(
      "client-state-list"
    );

  if (!container) return;

  container.innerHTML = "";

  if (!Array.isArray(clients) ||
      clients.length === 0) {

    container.innerHTML = `
      <div style="
        padding:20px;
        text-align:center;
        color:#64748b;">
        No DHCP clients tracked yet.
      </div>
    `;

    return;
  }

  clients.forEach(client => {
    const card =
      document.createElement("div");

    card.className =
      "client-state-card";

    card.innerHTML = `
      <div>

        <strong>
          ${escapeHtml(
            client.mac
          )}
        </strong>

        <div class="client-history">
          Requests:
          ${client.requests || 0}

          &nbsp; | &nbsp;

          Completed:
          ${client.completedTransactions || 0}

          &nbsp; | &nbsp;

          Incomplete:
          ${client.incompleteTransactions || 0}
        </div>

      </div>

      <span class="state-badge
        state-${String(
          client.state || "NEW"
        ).toLowerCase()}">

        ${escapeHtml(
          client.state || "NEW"
        )}

      </span>
    `;

    container.appendChild(card);
  });
}


// ============================================================
// ADD DHCP TRANSACTION BUTTON
// ============================================================

function addDhcpTransactionButton() {
  const row =
    document.querySelector(
      ".quick-actions-row"
    );

  if (!row) return;

  if (
    document.getElementById(
      "dhcp-test-button"
    )
  ) {
    return;
  }

  const button =
    document.createElement("button");

  button.id =
    "dhcp-test-button";

  button.className =
    "action-btn";

  button.innerHTML = `
    <div class="action-icon-circle">
      ⚡
    </div>

    <span>
      Run DHCP Transaction
    </span>
  `;

  button.onclick =
    runDhcpTransaction;

  row.insertBefore(
    button,
    row.firstChild
  );
}


// ============================================================
// RUN DHCP TRANSACTION
// ============================================================

async function runDhcpTransaction() {
  const button =
    document.getElementById(
      "dhcp-test-button"
    );

  if (button) {
    button.disabled = true;

    button.innerHTML = `
      <div class="action-icon-circle">
        ⏳
      </div>

      <span>
        Processing...
      </span>
    `;
  }

  try {
    const response =
      await fetch(
        "/api/actions/lab-client",
        {
          method: "POST",

          headers: {
            "Content-Type":
              "application/json"
          },

          body: JSON.stringify({
            mac: "AA:BB:CC:DD:EE:03",
            mode: "transaction",
            deviceType: "Laptop"
          })
        }
      );

    const result =
      await response.json();

    if (!response.ok) {
      throw new Error(
        result.message ||
        "DHCP transaction failed."
      );
    }

    if (result.success) {
      const d = result.discover || {};
      const client = d.client || {};
      showToast(
        `DHCP transaction: ${d.decision || "ALLOW"} | ${client.state || "NEW"}${d.lease?.ip ? ` | ${d.lease.ip}` : ""}`,
        d.decision === "ALLOW" ? "success" : "danger"
      );
    } else {
      showToast(
        `Transaction failed`,
        "danger"
      );
    }

    await refreshDashboard();

  } catch (error) {
    console.error(error);

    showToast(
      error.message,
      "danger"
    );

  } finally {
    if (button) {
      button.disabled = false;

      button.innerHTML = `
        <div class="action-icon-circle">
          ⚡
        </div>

        <span>
          Run DHCP Transaction
        </span>
      `;
    }
  }
}


// ============================================================
// LEASE ROW MENU
// ============================================================

function openRowMenu(
  event,
  leaseId
) {
  event.stopPropagation();

  const dropdown =
    document.getElementById(
      "row-menu-dropdown"
    );

  if (!dropdown) return;

  currentSelectedLeaseId =
    Number(leaseId);

  currentSelectedLeaseData =
    allLeasesData.find(
      lease =>
        Number(lease.id) ===
        Number(leaseId)
    );

  const rect =
    event.target.getBoundingClientRect();

  dropdown.style.top =
    `${rect.bottom + window.scrollY + 4}px`;

  dropdown.style.left =
    `${rect.left + window.scrollX - 120}px`;

  dropdown.classList.add("show");
}


// ============================================================
// LEASE ACTIONS
// ============================================================

async function handleLeaseAction(
  action
) {
  const dropdown =
    document.getElementById(
      "row-menu-dropdown"
    );

  if (dropdown) {
    dropdown.classList.remove(
      "show"
    );
  }

  if (!currentSelectedLeaseId) {
    return;
  }

  const lease =
    currentSelectedLeaseData;

  if (!lease) return;


  // ----------------------------------------------------------
  // REVOKE
  // ----------------------------------------------------------

  if (action === "revoke") {
    const confirmed =
      confirm(
        `Are you sure you want to revoke lease for IP ${lease.ip}?`
      );

    if (!confirmed) return;

    try {
      const response =
        await fetch(
          `/api/leases/${currentSelectedLeaseId}`,
          {
            method: "DELETE"
          }
        );

      const result =
        await response.json();

      if (!response.ok) {
        throw new Error(
          result.message ||
          "Failed to revoke lease."
        );
      }

      showToast(
        `Lease ${lease.ip} revoked.`,
        "info"
      );

      await refreshDashboard();

    } catch (error) {
      showToast(
        error.message,
        "danger"
      );
    }

    return;
  }


  // ----------------------------------------------------------
  // RENEW
  // ----------------------------------------------------------

  if (action === "renew") {
    try {
      const response =
        await fetch(
          `/api/leases/${currentSelectedLeaseId}/renew`,
          {
            method: "POST"
          }
        );

      const result =
        await response.json();

      if (!response.ok) {
        throw new Error(
          result.message ||
          "Failed to renew lease."
        );
      }

      showToast(
        `Lease ${lease.ip} renewed for 2 hours.`,
        "success"
      );

      await refreshDashboard();

    } catch (error) {
      showToast(
        error.message,
        "danger"
      );
    }

    return;
  }


  // ----------------------------------------------------------
  // COPY MAC
  // ----------------------------------------------------------

  if (action === "copy") {
    try {
      await navigator.clipboard.writeText(
        lease.mac
      );

      showToast(
        `Copied MAC ${lease.mac}.`,
        "info"
      );

    } catch {
      showToast(
        "Unable to copy MAC.",
        "danger"
      );
    }
  }
}


// ============================================================
// IP RANGE MODAL
// ============================================================

async function saveIpRange() {
  const startInput =
    document.getElementById(
      "input-start-ip"
    );

  const endInput =
    document.getElementById(
      "input-end-ip"
    );

  if (!startInput || !endInput) {
    showToast(
      "IP range fields not found.",
      "danger"
    );

    return;
  }

  const start =
    parseInt(
      startInput.value,
      10
    );

  const end =
    parseInt(
      endInput.value,
      10
    );

  if (
    Number.isNaN(start) ||
    Number.isNaN(end) ||
    start >= end ||
    start < 1 ||
    end > 254
  ) {
    showToast(
      "Please enter a valid IP range.",
      "danger"
    );

    return;
  }

  try {
    const response =
      await fetch(
        "/api/actions/pool-range",
        {
          method: "POST",

          headers: {
            "Content-Type":
              "application/json"
          },

          body: JSON.stringify({
            start,
            end
          })
        }
      );

    const result =
      await response.json();

    if (!response.ok) {
      throw new Error(
        result.message ||
        "Failed to update pool."
      );
    }

    closeModal(
      "addRangeModal"
    );

    showToast(
      `IP pool updated: ${start} - ${end}`,
      "success"
    );

    await refreshDashboard();

  } catch (error) {
    showToast(
      error.message,
      "danger"
    );
  }
}


// ============================================================
// RESTART SERVER / ENGINE
// ============================================================

async function restartServer() {
  const button =
    document.getElementById(
      "btn-restart-server"
    );

  let original =
    null;

  if (button) {
    original =
      button.innerHTML;

    button.disabled = true;

    button.innerHTML = `
      <div class="action-icon-circle">
        ⟳
      </div>

      <span>
        Reloading...
      </span>
    `;
  }

  try {
    const response =
      await fetch(
        "/api/actions/restart",
        {
          method: "POST"
        }
      );

    const result =
      await response.json();

    if (!response.ok) {
      throw new Error(
        result.message ||
        "Unable to reload engine."
      );
    }

    showToast(
      "DHCPd-Guard engine reloaded successfully.",
      "success"
    );

    await refreshDashboard();

  } catch (error) {
    showToast(
      error.message,
      "danger"
    );

  } finally {
    if (button) {
      button.disabled = false;

      button.innerHTML =
        original;
    }
  }
}


// ============================================================
// SIMULATE ATTACK
// ============================================================

async function simulateAttackPrompt() {
  const choice =
    confirm(
      "Click OK for DHCP Starvation event.\n\n" +
      "Click Cancel for Rogue DHCP event."
    );

  const type =
    choice
      ? "starvation"
      : "rogue";

  await simulateAttack(type);
}


async function simulateAttack(
  type
) {
  try {
    const response =
      await fetch(
        "/api/actions/simulate-attack",
        {
          method: "POST",

          headers: {
            "Content-Type":
              "application/json"
          },

          body: JSON.stringify({
            attackType: type
          })
        }
      );

    const result =
      await response.json();

    if (!response.ok) {
      throw new Error(
        result.message ||
        "Simulation failed."
      );
    }

    if (result.event) {
      notifySecurityEventOnce(result.event);
    }

    showToast(
      `${type} security event blocked.`,
      "danger"
    );

    await refreshDashboard();

  } catch (error) {
    showToast(
      error.message,
      "danger"
    );
  }
}


// ============================================================
// SECURITY RULES
// ============================================================

async function toggleRule(id, enabled) {
  try {
    const response = await fetch(`/api/rules/${id}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled })
    });

    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Failed to update rule.");

    const index = allRulesData.findIndex(r => Number(r.id) === Number(id));
    if (index !== -1) allRulesData[index] = result.rule;
    renderSecurityRules(allRulesData);
    showToast(`${result.rule.name}: ${result.rule.status}`, "success");
  } catch (error) {
    showToast(error.message, "danger");
    renderSecurityRules(allRulesData);
  }
}


function saveRules() {
  closeModal(
    "rulesModal"
  );

  showToast(
    "Security rules applied.",
    "success"
  );
}


// ============================================================
// MODALS
// ============================================================

function openModal(id) {
  const modal =
    document.getElementById(id);

  if (!modal) {
    console.warn(
      "Modal not found:",
      id
    );

    return;
  }

  modal.classList.add(
    "show"
  );

  // Render latest information when opening
  if (id === "allLeasesModal") {
    renderLeasesTable(
      allLeasesData
    );
  }

  if (id === "logsModal") {
    renderFullLogs(
      allEventsData,
      document.getElementById(
        "full-logs-container"
      )
    );
  }

  if (id === "rulesModal") {
    renderSecurityRules(
      allRulesData
    );
  }
}


function closeModal(id) {
  const modal =
    document.getElementById(id);

  if (!modal) return;

  modal.classList.remove(
    "show"
  );
}


// ============================================================
// LOG FILTER
// ============================================================

function setLogFilter(
  type,
  clickedButton
) {
  document
    .querySelectorAll(
      ".filter-pills .pill"
    )
    .forEach(button => {
      button.classList.remove(
        "active"
      );
    });

  if (clickedButton) {
    clickedButton.classList.add(
      "active"
    );
  }

  let filtered =
    allEventsData;

  if (
    type !== "all"
  ) {
    filtered =
      allEventsData.filter(
        event => {
          const eventType =
            String(
              event.type || ""
            ).toLowerCase();

          const status =
            String(
              event.status || ""
            ).toLowerCase();

          return (
            eventType === type ||
            status === type
          );
        }
      );
  }

  renderFullLogs(
    filtered,
    document.getElementById(
      "full-logs-container"
    )
  );
}


function filterLogs(
  query
) {
  const q =
    String(query || "")
      .toLowerCase()
      .trim();

  if (!q) {
    renderFullLogs(
      allEventsData,
      document.getElementById(
        "full-logs-container"
      )
    );

    return;
  }

  const filtered =
    allEventsData.filter(
      event => {
        const text = [
          event.time,
          event.title,
          event.message,
          event.detail,
          event.type,
          event.status
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();

        return text.includes(q);
      }
    );

  renderFullLogs(
    filtered,
    document.getElementById(
      "full-logs-container"
    )
  );
}


// ============================================================
// EXPORT LOGS
// ============================================================

function exportLogs() {
  const rows = [
    [
      "Time",
      "Event",
      "Detail",
      "Status"
    ]
  ];

  allEventsData.forEach(
    event => {
      rows.push([
        event.time || "",
        event.title ||
          event.message ||
          "",
        event.detail ||
          event.message ||
          "",
        event.status ||
          event.type ||
          ""
      ]);
    }
  );

  const csv =
    rows
      .map(row =>
        row
          .map(csvEscape)
          .join(",")
      )
      .join("\n");

  const blob =
    new Blob(
      [csv],
      {
        type:
          "text/csv;charset=utf-8;"
      }
    );

  const url =
    URL.createObjectURL(blob);

  const link =
    document.createElement("a");

  link.href = url;

  link.download =
    `dhcpd_guard_logs_${Date.now()}.csv`;

  document.body.appendChild(
    link
  );

  link.click();

  document.body.removeChild(
    link
  );

  URL.revokeObjectURL(
    url
  );
}


function csvEscape(value) {
  return `"${String(
    value ?? ""
  ).replaceAll(
    '"',
    '""'
  )}"`;
}


// ============================================================
// NOTIFICATIONS
// ============================================================

function toggleNotifications() {
  const dropdown =
    document.getElementById(
      "notif-dropdown"
    );

  if (dropdown) {
    dropdown.classList.toggle(
      "show"
    );
  }
}


// ============================================================
// CLIENT STATES BUTTON
// ============================================================

function addClientStateButton() {
  const row =
    document.querySelector(
      ".quick-actions-row"
    );

  if (!row) return;

  if (
    document.getElementById(
      "client-state-button"
    )
  ) {
    return;
  }

  const button =
    document.createElement(
      "button"
    );

  button.id =
    "client-state-button";

  button.className =
    "action-btn";

  button.innerHTML = `
    <div class="action-icon-circle">
      👥
    </div>

    <span>
      Client States
    </span>
  `;

  button.onclick =
    showClientStates;

  row.appendChild(
    button
  );
}


// ============================================================
// CLIENT STATES MODAL
// ============================================================

async function showClientStates() {
  let overlay =
    document.getElementById(
      "client-state-overlay"
    );

  if (overlay) {
    overlay.remove();
  }

  overlay =
    document.createElement(
      "div"
    );

  overlay.id =
    "client-state-overlay";

  overlay.style.cssText = `
    position:fixed;
    inset:0;
    background:rgba(15,23,42,.55);
    display:flex;
    align-items:center;
    justify-content:center;
    z-index:9999;
  `;

  const modal =
    document.createElement(
      "div"
    );

  modal.style.cssText = `
    background:#fff;
    width:min(800px,90vw);
    max-height:80vh;
    overflow:auto;
    border-radius:14px;
    padding:24px;
  `;

  modal.innerHTML = `
    <div style="
      display:flex;
      justify-content:space-between;
      align-items:center;
      margin-bottom:20px;">

      <h2>
        Client State Tracking
      </h2>

      <button
        onclick="
          document
            .getElementById(
              'client-state-overlay'
            )
            .remove()
        "
        style="
          border:0;
          background:none;
          font-size:22px;
          cursor:pointer;">
        ×
      </button>

    </div>

    <div id="client-state-list">
      Loading...
    </div>
  `;

  overlay.appendChild(
    modal
  );

  document.body.appendChild(
    overlay
  );


  try {
    const response =
      await fetch(
        "/api/clients"
      );

    const clients =
      await response.json();

    renderClientStates(
      clients
    );

  } catch (error) {
    const container =
      document.getElementById(
        "client-state-list"
      );

    if (container) {
      container.innerHTML = `
        <p>
          Unable to load client states.
        </p>
      `;
    }
  }
}


// ============================================================
// SSE LIVE EVENTS
// ============================================================

function setupSSE() {
  if (
    typeof EventSource ===
    "undefined"
  ) {
    return;
  }

  const source =
    new EventSource(
      "/api/events/live"
    );

  source.onopen = () => {
    console.log(
      "DHCPd-Guard live connection established."
    );
  };


  source.onmessage =
    async event => {
      try {
        const data =
          JSON.parse(
            event.data
          );

        switch (
          data.type
        ) {

          case "CONNECTED":
            break;


          case "NEW_LEASE":
            showToast(
              "New DHCP lease assigned.",
              "success"
            );

            await refreshDashboard();
            break;


          case "REVOKE_LEASE":
            showToast(
              "DHCP lease revoked.",
              "info"
            );

            await refreshDashboard();
            break;


          case "LEASE_RENEWED":
            showToast(
              "DHCP lease renewed.",
              "success"
            );

            await refreshDashboard();
            break;


          case "DHCP_DECISION":
            showDecisionToast(
              data
            );
            break;


          case "DHCP_OFFER":
            showToast(
              `IP ${data.ip} reserved for ${data.mac}.`,
              "success"
            );
            break;


          case "DHCP_REQUEST_ACCEPTED":
            showToast(
              `DHCP request accepted for ${data.mac}.`,
              "success"
            );
            break;


          case "CLIENT_STATE_UPDATE":
            await refreshDashboard();
            break;


          case "ATTACK_BLOCKED":
            if (data.event) {
              notifySecurityEventOnce(data.event);
            }

            showToast(
              "Security event detected and blocked.",
              "danger"
            );

            await refreshDashboard();
            break;


          case "STATS_UPDATE":
            if (data.stats) {
              updateStatsUI(
                data.stats
              );
            }

            await refreshDashboard();
            break;


          case "POOL_UPDATED":
            await refreshDashboard();
            break;


          case "RULES_UPDATED":
            allRulesData =
              data.rules || [];

            renderSecurityRules(
              allRulesData
            );

            break;


          case "SERVER_RESTARTED":
            showToast(
              "DHCPd-Guard engine reloaded.",
              "success"
            );

            await refreshDashboard();
            break;

        }

      } catch (error) {
        console.error(
          "SSE error:",
          error
        );
      }
    };


  source.onerror = () => {
    console.warn(
      "Live connection interrupted. Browser will reconnect automatically."
    );
  };
}


// ============================================================
// DECISION TOAST
// ============================================================

function showDecisionToast(
  data
) {
  const decision =
    String(
      data.decision || ""
    ).toUpperCase();

  if (
    decision === "ALLOW"
  ) {
    showToast(
      `${data.mac} → ALLOW | ${data.state} | ${data.pressure}`,
      "success"
    );
  }

  else if (
    decision === "RESTRICT"
  ) {
    showToast(
      `${data.mac} → RESTRICT | ${data.state} | ${data.pressure}`,
      "info"
    );
  }

  else if (
    decision === "DENY"
  ) {
    showToast(
      `${data.mac} → DENY | ${data.state}`,
      "danger"
    );
  }
}


// ============================================================
// CLICK OUTSIDE
// ============================================================

function setupClickOutside() {
  window.addEventListener(
    "click",
    event => {

      const notification =
        document.getElementById(
          "notif-dropdown"
        );

      const wrapper =
        document.getElementById(
          "notif-wrapper"
        );

      if (
        notification &&
        wrapper &&
        !wrapper.contains(
          event.target
        )
      ) {
        notification.classList.remove(
          "show"
        );
      }


      const dropdown =
        document.getElementById(
          "row-menu-dropdown"
        );

      if (
        dropdown &&
        !event.target.closest(
          ".table-action-btn"
        )
      ) {
        dropdown.classList.remove(
          "show"
        );
      }
    }
  );
}


// ============================================================
// TOAST
// ============================================================

function showToast(
  message,
  type = "info"
) {
  const container =
    document.getElementById(
      "toast-container"
    );

  if (!container) {
    console.log(
      `[${type}]`,
      message
    );

    return;
  }

  const toast =
    document.createElement(
      "div"
    );

  toast.className =
    `toast ${type}`;

  toast.innerHTML = `
    <span>
      ${escapeHtml(message)}
    </span>
  `;

  container.appendChild(
    toast
  );

  setTimeout(() => {
    toast.style.opacity =
      "0";

    toast.style.transform =
      "translateX(20px)";

    toast.style.transition =
      "all .3s ease";

    setTimeout(
      () => toast.remove(),
      300
    );

  }, 4000);
}


// ============================================================
// HELPERS
// ============================================================

function setText(
  id,
  value
) {
  const element =
    document.getElementById(
      id
    );

  if (element) {
    element.textContent =
      value ?? "-";
  }
}


function escapeHtml(
  value
) {
  return String(
    value ?? ""
  )
    .replaceAll(
      "&",
      "&amp;"
    )
    .replaceAll(
      "<",
      "&lt;"
    )
    .replaceAll(
      ">",
      "&gt;"
    )
    .replaceAll(
      '"',
      "&quot;"
    )
    .replaceAll(
      "'",
      "&#039;"
    );
}


// ============================================================
// GLOBAL FUNCTIONS
// ============================================================

window.openModal =
  openModal;

window.closeModal =
  closeModal;

window.saveIpRange =
  saveIpRange;

window.restartServer =
  restartServer;

window.simulateAttackPrompt =
  simulateAttackPrompt;

window.simulateAttack =
  simulateAttack;

window.toggleRule =
  toggleRule;

window.saveRules =
  saveRules;

window.setLogFilter =
  setLogFilter;

window.filterLogs =
  filterLogs;

window.exportLogs =
  exportLogs;

window.toggleNotifications =
  toggleNotifications;

window.openRowMenu =
  openRowMenu;

window.handleLeaseAction =
  handleLeaseAction;

window.runDhcpTransaction =
  runDhcpTransaction;

window.showClientStates =
  showClientStates;
  // ============================================================
// REAL SECURITY NOTIFICATIONS
// ============================================================

let unreadNotifications = 0;
let securityNotifications = [];
let notifiedSecurityEventIds = new Set();

function notifySecurityEventOnce(event) {
  if (!event) return;
  const id = getEventId(event);
  if (notifiedSecurityEventIds.has(id)) return;
  notifiedSecurityEventIds.add(id);
  addSecurityNotification(
    "Security Event Blocked",
    event.detail || event.message || event.title || "A DHCP security event was blocked.",
    "red"
  );
}

function initializeNotifications() {
  // Remove the fake hard-coded "3"
  unreadNotifications = 0;
  securityNotifications = [];

  updateNotificationUI();
}

function addSecurityNotification(
  title,
  message,
  type = "red"
) {
  securityNotifications.unshift({
    title,
    message,
    type,
    time: new Date().toLocaleTimeString(
      [],
      {
        hour: "2-digit",
        minute: "2-digit"
      }
    )
  });

  unreadNotifications++;

  // Keep only latest 10
  securityNotifications =
    securityNotifications.slice(0, 10);

  updateNotificationUI();
}

function updateNotificationUI() {
  const badge =
    document.getElementById(
      "notif-badge"
    );

  const count =
    document.querySelector(
      ".notif-count"
    );

  const list =
    document.querySelector(
      ".notif-list"
    );

  // Badge
  if (badge) {
    if (unreadNotifications > 0) {
      badge.textContent =
        unreadNotifications;

      badge.style.display =
        "flex";
    } else {
      badge.style.display =
        "none";
    }
  }

  // Header count
  if (count) {
    count.textContent =
      unreadNotifications > 0
        ? `${unreadNotifications} new`
        : "No new alerts";
  }

  // Notification list
  if (list) {
    if (
      securityNotifications.length === 0
    ) {
      list.innerHTML = `
        <div style="
          padding:20px;
          text-align:center;
          color:#64748b;">
          No new security alerts.
        </div>
      `;

      return;
    }

    list.innerHTML =
      securityNotifications
        .map(notification => `
          <div class="notif-item alert">

            <span class="
              notif-dot
              ${notification.type}
            "></span>

            <div class="notif-info">

              <strong>
                ${escapeHtml(
                  notification.title
                )}
              </strong>

              <p>
                ${escapeHtml(
                  notification.message
                )}
              </p>

              <small>
                ${escapeHtml(
                  notification.time
                )}
              </small>

            </div>

          </div>
        `)
        .join("");
  }
}


// Mark notifications as read
function markNotificationsRead() {
  unreadNotifications = 0;

  updateNotificationUI();
}


// Replace notification toggle
function toggleNotifications() {
  const dropdown =
    document.getElementById(
      "notif-dropdown"
    );

  if (!dropdown) return;

  dropdown.classList.toggle(
    "show"
  );

  // Opening the bell marks them as read
  if (
    dropdown.classList.contains(
      "show"
    )
  ) {
    markNotificationsRead();
  }
}


// Initialize on page load
document.addEventListener(
  "DOMContentLoaded",
  () => {
    initializeNotifications();
  }
);
// ============================================================
// DETECT NEW SECURITY EVENTS
// ============================================================

let knownSecurityEventIds = new Set();

function processNewSecurityEvents(events) {

  if (!Array.isArray(events)) return;

  // First dashboard load:
  // existing old events ko notification mat banao.
  if (knownSecurityEventIds.size === 0) {

    events.forEach(event => {
      if (
        isSecurityEvent(event)
      ) {
        knownSecurityEventIds.add(
          getEventId(event)
        );
      }
    });

    return;
  }


  events.forEach(event => {

    if (!isSecurityEvent(event)) {
      return;
    }

    const eventId =
      getEventId(event);

    if (
      knownSecurityEventIds.has(
        eventId
      )
    ) {
      return;
    }

    knownSecurityEventIds.add(
      eventId
    );


    notifySecurityEventOnce(event);

  });
}


function isSecurityEvent(event) {

  const type =
    String(
      event.type || ""
    ).toLowerCase();

  const status =
    String(
      event.status || ""
    ).toLowerCase();

  const title =
    String(
      event.title || ""
    ).toLowerCase();

  const message =
    String(
      event.message || ""
    ).toLowerCase();

  return (
    type === "danger" ||
    type === "attack" ||
    status === "blocked" ||
    title.includes("attack") ||
    message.includes("attack") ||
    message.includes("blocked")
  );
}


function getEventId(event) {

  return (
    event.id ||
    `${event.time}-${event.title}-${event.message}`
  );
}