# VANET Secure Routing Protocol

A Python implementation of a secure routing protocol for Vehicular Ad Hoc Networks (VANET) using digital signatures and hash functions to prevent attacks like data tampering, impersonation, and message modification.

## Features

- **Vehicle Mobility Model**: Realistic vehicle movement simulation with dynamic speed and direction changes
- **Secure Message Exchange**: Implementation of digital signatures and hash functions for secure communication
- **Routing Protocol**: Advanced routing mechanism with security features
- **Attack Simulation**: Built-in capability to simulate and detect various network attacks
- **Performance Metrics**: Comprehensive metrics calculation and analysis
- **Visualization**: Real-time visualization of network topology and vehicle movements

## Requirements

### Python Dependencies
- numpy
- pandas
- matplotlib
- networkx
- cryptography

### NS-3 Requirements
- NS-3 network simulator (ns-3-dev)
- Python bindings enabled
- Required NS-3 modules:
  - core
  - network
  - applications
  - mobility
  - internet
  - wifi
  - wave
  - aodv
  - dsr
  - olsr

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Banarji03/VANET-Security-NS3.git

2. Install Python dependencies:
  ```bash
pip install -r requirements.txt

3. Build NS-3 with Python bindings:
  ```bash
 1 cd ns-3-dev
 2 ./ns3 configure --enable-python-bindings
 3 ./ns3 build

### To Run

1. Run the simulation:
   ```bash
   python main.py
2. Run NS-3 integration:
  ```bash
python ns3_integration.py

#### Results
The simulation results, including network topology, vehicle movements, and performance metrics, will be saved in the output directory.
