#pragma once

// Initialize provisioning (registers event handlers, checks if already provisioned)
void provisioning_init();

// Start BLE provisioning manually (e.g., for button-triggered re-provisioning)
void provisioning_start();