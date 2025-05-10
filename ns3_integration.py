import ns.core
import ns.network
import ns.applications
import ns.mobility
import ns.internet
import ns.wifi
import ns.wave  # For WAVE/DSRC support
import ns.aodv
import ns.dsr
import ns.olsr
from main import Vehicle, VANETSimulator, CryptoManager

def create_ns3_vanet_simulation():
    """Create a VANET simulation using NS-3"""
    # Create NS-3 simulation context
    ns.core.LogComponentEnable("VanetRoutingExample", ns.core.LOG_LEVEL_INFO)
    
    # Create nodes for vehicles
    nodes = ns.network.NodeContainer()
    nodes.Create(20)  # 20 vehicles as in our Python simulation
    
    # Configure mobility model (use SUMO integration for realistic mobility)
    mobility = ns.mobility.MobilityHelper()
    mobility.SetMobilityModel("ns3::RandomWaypointMobilityModel",
                             "Speed", ns.core.StringValue("ns3::UniformRandomVariable[Min=10.0|Max=30.0]"),
                             "Pause", ns.core.StringValue("ns3::ConstantRandomVariable[Constant=0.0]"),
                             "PositionAllocator", ns.core.StringValue("ns3::RandomRectanglePositionAllocator"))
    
    # Set position allocator parameters
    position_alloc = ns.mobility.RandomRectanglePositionAllocator()
    position_alloc.SetX(ns.core.UniformRandomVariable(0.0, 1000.0))
    position_alloc.SetY(ns.core.UniformRandomVariable(0.0, 1000.0))
    mobility.SetPositionAllocator(position_alloc)
    mobility.Install(nodes)
    
    # Set up WAVE/DSRC devices
    wave_helper = ns.wave.YansWaveHelper()
    devices = wave_helper.Install(nodes)
    
    # Install internet stack
    internet = ns.internet.InternetStackHelper()
    internet.Install(nodes)
    
    # Create custom routing protocol application
    # This is where you'll implement your secure routing protocol
    app_helper = ns.applications.ApplicationHelper("SecureVanetRouting")
    apps = app_helper.Install(nodes)
    
    # Configure malicious nodes (10% as in Python simulation)
    malicious_count = int(0.1 * nodes.GetN())
    for i in range(malicious_count):
        node_id = i  # First few nodes are malicious
        apps.Get(node_id).SetAttribute("Malicious", ns.core.BooleanValue(True))
    
    # Run simulation
    ns.core.Simulator.Stop(ns.core.Seconds(100.0))
    ns.core.Simulator.Run()
    ns.core.Simulator.Destroy()

# Main function
if __name__ == "__main__":
    create_ns3_vanet_simulation()


import ns.core
import ns.network
import ns.applications
import ns.mobility
import ns.wifi
import ns.internet
import ns.aodv
import ns.dsr
import ns.olsr


class NS3VANETIntegration:
    def __init__(self, simulator):
        self.simulator = simulator
        ns.core.Config.SetDefault("ns3::WifiRemoteStationManager::RtsCtsThreshold", ns.core.UintegerValue(2200))
        ns.core.Config.SetDefault("ns3::WifiRemoteStationManager::FragmentationThreshold", ns.core.StringValue("2200"))
        
        # Enhanced security configuration
        ns.core.Config.SetDefault("ns3::WifiRemoteStationManager::AuthTimeout", ns.core.TimeValue(ns.core.Seconds(5)))
        ns.core.Config.SetDefault("ns3::WifiMac::MaxRetries", ns.core.UintegerValue(7))
        
        self.nodes = ns.network.NodeContainer()
        self.devices = None
        self.mobility = None
        self.setup_nodes()

    def setup_nodes(self):
        # Create nodes for each vehicle
        self.nodes.Create(len(self.simulator.vehicles))

        # Setup WiFi with 802.11p
        wifi = ns.wifi.WifiHelper()
        wifi.SetStandard(ns.wifi.WIFI_STANDARD_80211p)
        
        # Enhanced rate control
        wifi.SetRemoteStationManager("ns3::MinstrelWifiManager",
                                   "RtsCtsThreshold", ns.core.UintegerValue(2200),
                                   "FragmentationThreshold", ns.core.StringValue("2200"),
                                   "OutputFileName", ns.core.StringValue("minstrel-stats.txt"))

        # Configure MAC layer
        wifiMac = ns.wifi.WifiMacHelper()
        wifiMac.SetType("ns3::AdhocWifiMac",
                       "QosSupported", ns.core.BooleanValue(True),
                       "BE_MaxAmpduSize", ns.core.UintegerValue(0))

        # Enhanced PHY layer configuration
        wifiPhy = ns.wifi.YansWifiPhyHelper()
        wifiChannel = ns.wifi.YansWifiChannelHelper.Default()
        wifiChannel.AddPropagationLoss("ns3::NakagamiPropagationLossModel")
        wifiChannel.AddPropagationDelay("ns3::ConstantSpeedPropagationDelayModel")
        wifiPhy.SetChannel(wifiChannel.Create())
        
        # Set transmit power and other PHY parameters
        wifiPhy.Set("TxPowerStart", ns.core.DoubleValue(20.0))
        wifiPhy.Set("TxPowerEnd", ns.core.DoubleValue(20.0))
        wifiPhy.Set("TxGain", ns.core.DoubleValue(2.0))
        wifiPhy.Set("RxGain", ns.core.DoubleValue(2.0))

        self.devices = wifi.Install(wifiPhy, wifiMac, self.nodes)

        # Setup Internet stack with multiple routing protocols
        internet = ns.internet.InternetStackHelper()
        
        # Add AODV routing
        aodv = ns.aodv.AodvHelper()
        internet.SetRoutingHelper(aodv)
        
        # Optional: Add DSR and OLSR for comparison
        self.routing_protocols = {
            "AODV": aodv,
            "DSR": ns.dsr.DsrHelper(),
            "OLSR": ns.olsr.OlsrHelper()
        }
        
        internet.Install(self.nodes)

        # Enhanced mobility model
        self.mobility = ns.mobility.MobilityHelper()
        self.mobility.SetMobilityModel("ns3::WaypointMobilityModel")
        self.mobility.Install(self.nodes)

    def update_node_positions(self):
        for i, vehicle in enumerate(self.simulator.vehicles):
            node = self.nodes.Get(i)
            mobility = node.GetObject(ns.mobility.MobilityModel.GetTypeId())
            
            # Update position and velocity
            pos = ns.core.Vector3D(vehicle.position[0], vehicle.position[1], 1.5)  # 1.5m height
            vel = ns.core.Vector3D(vehicle.speed * np.cos(vehicle.direction),
                                 vehicle.speed * np.sin(vehicle.direction),
                                 0.0)
            
            # Add waypoint for smooth movement
            mobility.AddWaypoint(ns.mobility.Waypoint(ns.core.Seconds(ns.core.Simulator.Now().GetSeconds()),
                                                    pos, vel))

    def setup_applications(self):
        for i, vehicle in enumerate(self.simulator.vehicles):
            # Create VANET application
            app = self.create_vanet_application(i)
            node = self.nodes.Get(i)
            node.AddApplication(app)
            
            # Add security monitor application
            monitor = self.create_security_monitor(i)
            node.AddApplication(monitor)

    def create_vanet_application(self, node_id):
        app = ns.core.TypeId.LookupByName("ns3::UdpEchoClient")
        client = ns.core.CreateObject(app)
        
        # Enhanced configuration
        client.SetAttribute("MaxPackets", ns.core.UintegerValue(1000))
        client.SetAttribute("Interval", ns.core.TimeValue(ns.core.Seconds(0.1)))
        client.SetAttribute("PacketSize", ns.core.UintegerValue(1024))
        client.SetAttribute("RemotePort", ns.core.UintegerValue(9))
        
        return client

    def create_security_monitor(self, node_id):
        # Custom security monitoring application
        monitor = ns.core.TypeId.LookupByName("ns3::Application")
        app = ns.core.CreateObject(monitor)
        
        # Add security monitoring capabilities
        app.SetAttribute("MonitorInterval", ns.core.TimeValue(ns.core.Seconds(1.0)))
        app.SetAttribute("DetectionThreshold", ns.core.DoubleValue(0.8))
        
        return app

    def run_simulation(self, duration):
        ns.core.Simulator.Stop(ns.core.Seconds(duration))
        
        # Schedule periodic updates
        def schedule_update(simulator):
            simulator.update_node_positions()
            if ns.core.Simulator.Now().GetSeconds() < duration:
                ns.core.Simulator.Schedule(ns.core.Seconds(0.1), schedule_update, simulator)
        
        ns.core.Simulator.Schedule(ns.core.Seconds(0.0), schedule_update, self)
        
        # Run simulation
        ns.core.Simulator.Run()
        ns.core.Simulator.Destroy()

def integrate_with_ns3(vanet_sim, duration=100.0):
    """Integrate VANET simulation with NS-3"""
    ns3_integration = NS3VANETIntegration(vanet_sim)
    ns3_integration.setup_applications()
    ns3_integration.run_simulation(duration)
    return ns3_integration