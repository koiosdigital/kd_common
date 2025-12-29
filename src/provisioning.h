#pragma once

// Initialize provisioning - checks if already provisioned (call AFTER wifi_init)
void provisioning_init();

// Start BLE provisioning manually (e.g., for button-triggered re-provisioning)
void provisioning_start();