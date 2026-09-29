'use strict';

const STATES = {
  NEW: 'NEW',
  PROBATION: 'PROBATION',
  STABLE: 'STABLE',
  SUSPICIOUS: 'SUSPICIOUS',
  QUARANTINED: 'QUARANTINED'
};

class ClientStateTracker {
  constructor() {
    this.clients = new Map();
  }

  getClient(mac) {
    if (!this.clients.has(mac)) {
      this.clients.set(mac, {
        mac,
        state: STATES.NEW,
        requests: 0,
        completedTransactions: 0,
        incompleteTransactions: 0,
        firstSeen: Date.now(),
        lastSeen: Date.now()
      });
    }
    return this.clients.get(mac);
  }

  recordDiscover(mac) {
    const client = this.getClient(mac);
    client.requests += 1;
    client.incompleteTransactions += 1;
    client.lastSeen = Date.now();
    this.updateState(client);
    return client;
  }

  recordCompletedTransaction(mac) {
    const client = this.getClient(mac);
    client.completedTransactions += 1;
    if (client.incompleteTransactions > 0) client.incompleteTransactions -= 1;
    client.lastSeen = Date.now();
    this.updateState(client);
    return client;
  }

  updateState(client) {
    const { requests, completedTransactions, incompleteTransactions } = client;
    if (requests <= 1) {
      client.state = STATES.NEW;
      return;
    }
    if (incompleteTransactions >= 5 && requests >= 5) {
      client.state = STATES.SUSPICIOUS;
      return;
    }
    if (completedTransactions >= 2 && incompleteTransactions <= 1) {
      client.state = STATES.STABLE;
      return;
    }
    client.state = STATES.PROBATION;
  }

  getState(mac) {
    return this.getClient(mac).state;
  }

  getAllClients() {
    return Array.from(this.clients.values());
  }
}

module.exports = { STATES, ClientStateTracker };
