-- Devices seen on the network, so the device overview survives a restart.
CREATE TABLE network_devices (
  mac TEXT PRIMARY KEY,
  addresses TEXT NOT NULL,
  hostname TEXT,
  first_seen_ms INTEGER NOT NULL,
  last_seen_ms INTEGER NOT NULL
);
CREATE INDEX idx_network_devices_last_seen ON network_devices(last_seen_ms);
