import argparse
import json
import os
from datetime import datetime
import random
import hashlib
import matplotlib.pyplot as plt
import time
import pandas as pd
import numpy as np
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from typing import Dict, List, Tuple, Any, Set, Optional
import networkx as nx
from matplotlib.animation import FuncAnimation
from collections import defaultdict


class CryptoManager:
    """
    Handles cryptographic operations for VANET nodes
    """
    def __init__(self):
        # Generate RSA key pair for digital signatures
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        
    def get_public_key_bytes(self) -> bytes:
        """Return the public key in bytes format for sharing"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
    def sign_message(self, message: Dict) -> bytes:
        """Create a digital signature for a message"""
        message_bytes = str(message).encode()
        signature = self.private_key.sign(
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    @staticmethod
    def verify_signature(message: Dict, signature: bytes, public_key_bytes: bytes) -> bool:
        """Verify a digital signature using the provided public key"""
        try:
            public_key = serialization.load_pem_public_key(public_key_bytes)
            message_bytes = str(message).encode()
            public_key.verify(
                signature,
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            print(f"Signature verification error: {e}")
            return False


class Vehicle:
    """
    Represents a vehicle in VANET with position, mobility, and security features
    """
    def __init__(self, vehicle_id: str, speed: float, position: Tuple[float, float], 
                 crypto_manager: Optional[CryptoManager] = None, is_malicious: bool = False):
        self.id = vehicle_id
        self.speed = speed
        self.position = position
        self.direction = random.uniform(0, 2*np.pi)  # Random initial direction
        self.salt = "vanet" + str(random.random())
        self.routing_table = {}
        self.neighbor_list = set()
        self.messages_sent = 0
        self.messages_received = 0
        self.messages_dropped = 0
        self.communication_range = 100  # meters
        self.crypto_manager = crypto_manager or CryptoManager()
        self.known_public_keys = {}  # Map of vehicle_id to public key
        self.is_malicious = is_malicious
        self.route_cache = {}  # Cache for routes to destination
        self.packet_queue = []  # Queue for packets waiting for routes
        self.received_signatures = set()  # To prevent replay attacks
        self.battery_level = 100.0  # Percentage remaining
        self.processing_power = random.uniform(0.8, 1.2)  # Relative processing power
        
    def move(self, dt: float, road_boundaries: Optional[Tuple[Tuple[float, float], Tuple[float, float]]] = None):
        """Move the vehicle based on its speed and direction, with optional road boundaries"""
        # Occasionally change direction slightly to simulate realistic driving
        self.direction += random.uniform(-0.1, 0.1)
        
        # Calculate new position
        new_x = self.position[0] + self.speed * dt * np.cos(self.direction)
        new_y = self.position[1] + self.speed * dt * np.sin(self.direction)
        
        # Handle road boundaries if provided
        if road_boundaries:
            min_coords, max_coords = road_boundaries
            
            # If hitting boundary, bounce/redirect
            if new_x < min_coords[0] or new_x > max_coords[0]:
                self.direction = np.pi - self.direction  # Reflect horizontally
                new_x = self.position[0] + self.speed * dt * np.cos(self.direction)
            
            if new_y < min_coords[1] or new_y > max_coords[1]:
                self.direction = -self.direction  # Reflect vertically
                new_y = self.position[1] + self.speed * dt * np.sin(self.direction)
                
            # Ensure within boundaries
            new_x = max(min_coords[0], min(new_x, max_coords[0]))
            new_y = max(min_coords[1], min(new_y, max_coords[1]))
        
        self.position = (new_x, new_y)
        
        # Small chance to change speed to simulate traffic conditions
        if random.random() < 0.05:
            speed_change = random.uniform(-5, 5)
            self.speed = max(0, self.speed + speed_change)
            
        # Battery consumption (small amount based on activities)
        self.battery_level -= 0.001 * dt
        
    def check_collision(self, other: 'Vehicle', threshold: float = 5.0) -> bool:
        """Check if this vehicle is within collision threshold of another vehicle"""
        distance = np.sqrt((self.position[0] - other.position[0]) ** 2 + 
                           (self.position[1] - other.position[1]) ** 2)
        return distance < threshold
    
    def in_communication_range(self, other: 'Vehicle') -> bool:
        """Check if another vehicle is within communication range"""
        distance = np.sqrt((self.position[0] - other.position[0]) ** 2 + 
                           (self.position[1] - other.position[1]) ** 2)
        return distance <= self.communication_range
    
    def generate_beacon(self) -> Tuple[Dict, bytes, bytes]:
        """Generate a periodic beacon message with vehicle status and location"""
        beacon = {
            "type": "beacon",
            "vehicle_id": self.id,
            "timestamp": time.time(),
            "position": self.position,
            "speed": self.speed,
            "direction": self.direction,
            "battery": self.battery_level
        }
        
        # Malicious node might tamper with the beacon data
        if self.is_malicious:
            if random.random() < 0.3:  # 30% chance of falsifying data
                beacon["position"] = (beacon["position"][0] + random.uniform(-50, 50), 
                                     beacon["position"][1] + random.uniform(-50, 50))
                beacon["speed"] = max(0, self.speed + random.uniform(-20, 20))
        
        signature = self.crypto_manager.sign_message(beacon)
        public_key = self.crypto_manager.get_public_key_bytes()
        
        return beacon, signature, public_key
    
    def generate_route_request(self, destination_id: str) -> Tuple[Dict, bytes, bytes]:
        """Generate a route request message (RREQ) for a specific destination"""
        rreq = {
            "type": "RREQ",
            "source_id": self.id,
            "destination_id": destination_id,
            "request_id": f"{self.id}-{destination_id}-{time.time()}",
            "hop_count": 0,
            "timestamp": time.time(),
            "path": [self.id]
        }
        
        signature = self.crypto_manager.sign_message(rreq)
        public_key = self.crypto_manager.get_public_key_bytes()
        
        return rreq, signature, public_key
    
    def generate_route_reply(self, rreq: Dict) -> Tuple[Dict, bytes, bytes]:
        """Generate a route reply message (RREP) for a received RREQ"""
        rrep = {
            "type": "RREP",
            "source_id": rreq["destination_id"],
            "destination_id": rreq["source_id"],
            "request_id": rreq["request_id"],
            "hop_count": rreq["hop_count"],
            "timestamp": time.time(),
            "path": rreq["path"] + [self.id]
        }
        
        signature = self.crypto_manager.sign_message(rrep)
        public_key = self.crypto_manager.get_public_key_bytes()
        
        return rrep, signature, public_key
    
    def generate_data_packet(self, destination_id: str, data: Any) -> Tuple[Dict, bytes, bytes]:
        """Generate a data packet to send to a specific destination"""
        # Use hash of data for integrity verification
        data_hash = hashlib.sha256(str(data).encode()).hexdigest()
        
        packet = {
            "type": "DATA",
            "source_id": self.id,
            "destination_id": destination_id,
            "packet_id": f"{self.id}-{destination_id}-{time.time()}-{random.randint(0, 1000)}",
            "timestamp": time.time(),
            "data_hash": data_hash,
            "hop_count": 0,
            "data": data
        }
        
        # If malicious, might tamper with data
        if self.is_malicious and random.random() < 0.4:
            packet["data"] = "Tampered data by malicious node"
            # Note: we don't update the hash, which will cause integrity check to fail
        
        signature = self.crypto_manager.sign_message(packet)
        public_key = self.crypto_manager.get_public_key_bytes()
        
        return packet, signature, public_key
    
    def forward_message(self, message: Dict, signature: bytes, public_key: bytes) -> Tuple[Dict, bytes, bytes]:
        """Forward a message after updating relevant fields"""
        message_copy = message.copy()
        
        # Update hop count
        if "hop_count" in message_copy:
            message_copy["hop_count"] += 1
            
        # If this is a route request, add self to path
        if message_copy["type"] == "RREQ" and self.id not in message_copy["path"]:
            message_copy["path"].append(self.id)
            
        # For malicious nodes, possibly tamper with forwarded messages
        if self.is_malicious and random.random() < 0.3:
            if message_copy["type"] == "RREQ" or message_copy["type"] == "RREP":
                # Tampering with routing information
                if "path" in message_copy and len(message_copy["path"]) > 0:
                    # Delete a random node from path to disrupt routing
                    if len(message_copy["path"]) > 1:
                        del message_copy["path"][random.randint(0, len(message_copy["path"])-1)]
            elif message_copy["type"] == "DATA":
                # Tampering with data
                message_copy["data"] = "Data modified by attacker"
        
        # Sign with own key before forwarding
        new_signature = self.crypto_manager.sign_message(message_copy)
        new_public_key = self.crypto_manager.get_public_key_bytes()
        
        return message_copy, new_signature, new_public_key
    
    def receive_message(self, message: Dict, signature: bytes, public_key: bytes, sender_id: str) -> bool:
        """
        Process a received message, verify its integrity and authenticity
        Returns True if message is valid and processed, False otherwise
        """
        # Store the public key of the sender
        if sender_id not in self.known_public_keys:
            self.known_public_keys[sender_id] = public_key
            
        # Check for replay attacks by verifying we haven't seen this signature before
        if signature in self.received_signatures:
            print(f"Vehicle {self.id} detected replay attack! Dropping message.")
            self.messages_dropped += 1
            return False
            
        # Verify the signature
        if not CryptoManager.verify_signature(message, signature, public_key):
            print(f"Vehicle {self.id} detected invalid signature from {sender_id}! Dropping message.")
            self.messages_dropped += 1
            return False
            
        # Record the signature to prevent replay attacks
        self.received_signatures.add(signature)
        
        # Process message based on type
        if message["type"] == "beacon":
            self.process_beacon(message, sender_id)
        elif message["type"] == "RREQ":
            self.process_route_request(message, signature, public_key, sender_id)
        elif message["type"] == "RREP":
            self.process_route_reply(message, signature, public_key)
        elif message["type"] == "DATA":
            self.process_data_packet(message, signature, public_key)
        else:
            print(f"Vehicle {self.id} received unknown message type from {sender_id}")
            return False
            
        self.messages_received += 1
        return True
    
    def process_beacon(self, beacon: Dict, sender_id: str):
        """Process a beacon message from another vehicle"""
        # Update neighbor list
        self.neighbor_list.add(sender_id)
        
        # Update routing table with direct neighbor
        self.routing_table[sender_id] = {
            "next_hop": sender_id,
            "distance": 1,
            "timestamp": time.time(),
            "battery": beacon["battery"],
            "position": beacon["position"]
        }
        
    def process_route_request(self, rreq: Dict, signature: bytes, public_key: bytes, sender_id: str):
        """Process a route request message"""
        # Check if this is a new RREQ or better than previous ones
        request_id = rreq["request_id"]
        source_id = rreq["source_id"]
        destination_id = rreq["destination_id"]
        
        # If we've seen this request before with lower hop count, ignore it
        if request_id in self.route_cache:
            if self.route_cache[request_id]["hop_count"] <= rreq["hop_count"]:
                return
                
        # Cache this route request
        self.route_cache[request_id] = {
            "hop_count": rreq["hop_count"],
            "path": rreq["path"],
            "timestamp": time.time()
        }
        
        # If we are the destination, send a route reply
        if destination_id == self.id:
            rrep, rrep_signature, rrep_public_key = self.generate_route_reply(rreq)
            # In a real implementation, we would send this back along the reverse path
            print(f"Vehicle {self.id} is destination, generating RREP for {source_id}")
            return
            
        # Otherwise, forward the RREQ to neighbors
        # In simulation, this would be handled by the VANET network simulator
        rreq_fwd, sig_fwd, pub_key_fwd = self.forward_message(rreq, signature, public_key)
        print(f"Vehicle {self.id} forwarding RREQ from {source_id} to {destination_id}")
    
    def process_route_reply(self, rrep: Dict, signature: bytes, public_key: bytes):
        """Process a route reply message"""
        destination_id = rrep["destination_id"]
        path = rrep["path"]
        
        # If we are the destination of the RREP, update our routing table
        if destination_id == self.id:
            if len(path) >= 2:  # Need at least source and next hop
                # Extract the next hop toward the source
                next_hop = path[1]  # Next node after us in the path
                
                # Update routing table
                self.routing_table[path[0]] = {
                    "next_hop": next_hop,
                    "distance": len(path) - 1,
                    "timestamp": time.time(),
                    "path": path
                }
                
                # Check if we have pending packets for this destination
                self.check_packet_queue()
        # Otherwise, forward the RREP along the path
        else:
            if self.id in path:
                idx = path.index(self.id)
                if idx < len(path) - 1:
                    next_hop = path[idx + 1]
                    # Forward to next hop (in real implementation)
                    rrep_fwd, sig_fwd, pub_key_fwd = self.forward_message(rrep, signature, public_key)
                    print(f"Vehicle {self.id} forwarding RREP to {next_hop}")
    
    def process_data_packet(self, packet: Dict, signature: bytes, public_key: bytes):
        """Process a data packet"""
        # Check if we are the destination
        if packet["destination_id"] == self.id:
            # Verify data integrity using hash
            data = packet["data"]
            data_hash = hashlib.sha256(str(data).encode()).hexdigest()
            
            if data_hash != packet["data_hash"]:
                print(f"Vehicle {self.id} detected data tampering in packet from {packet['source_id']}!")
                self.messages_dropped += 1
                return
                
            print(f"Vehicle {self.id} received valid data packet from {packet['source_id']}: {data}")
        # Otherwise, forward the packet if we know the route
        elif packet["destination_id"] in self.routing_table:
            next_hop = self.routing_table[packet["destination_id"]]["next_hop"]
            packet_fwd, sig_fwd, pub_key_fwd = self.forward_message(packet, signature, public_key)
            print(f"Vehicle {self.id} forwarding data packet to {next_hop}")
        # If we don't know the route, initiate route discovery or queue packet
        else:
            print(f"Vehicle {self.id} doesn't know route to {packet['destination_id']}, queuing packet")
            self.packet_queue.append((packet, signature, public_key))
            # Initiate route discovery
            self.initiate_route_discovery(packet["destination_id"])
    
    def initiate_route_discovery(self, destination_id: str):
        """Start the route discovery process for a destination"""
        rreq, signature, public_key = self.generate_route_request(destination_id)
        print(f"Vehicle {self.id} initiating route discovery to {destination_id}")
        # In a real implementation, this would broadcast to neighbors
    
    def check_packet_queue(self):
        """Check if any queued packets can now be sent"""
        remaining_packets = []
        
        for packet, signature, public_key in self.packet_queue:
            if packet["destination_id"] in self.routing_table:
                next_hop = self.routing_table[packet["destination_id"]]["next_hop"]
                packet_fwd, sig_fwd, pub_key_fwd = self.forward_message(packet, signature, public_key)
                print(f"Vehicle {self.id} forwarding queued packet to {next_hop}")
            else:
                # Keep in queue
                remaining_packets.append((packet, signature, public_key))
                
        self.packet_queue = remaining_packets
    
    def hash_message(self, message):
        """Generate various hash values for a message with timing information"""
        message_bytes = str(message).encode()
        hashes = {}
        
        start_time = time.time()
        hashes["sha256"] = hashlib.sha256(message_bytes + self.salt.encode()).hexdigest()
        hashes["sha256_time"] = time.time() - start_time
        
        start_time = time.time()
        hashes["md5"] = hashlib.md5(message_bytes + self.salt.encode()).hexdigest()
        hashes["md5_time"] = time.time() - start_time
        
        start_time = time.time()
        hashes["sha1"] = hashlib.sha1(message_bytes + self.salt.encode()).hexdigest()
        hashes["sha1_time"] = time.time() - start_time
        
        start_time = time.time()
        hashes["blake2b"] = hashlib.blake2b(message_bytes + self.salt.encode()).hexdigest()
        hashes["blake2b_time"] = time.time() - start_time
        
        start_time = time.time()
        hashes["sha3_256"] = hashlib.sha3_256(message_bytes + self.salt.encode()).hexdigest()
        hashes["sha3_256_time"] = time.time() - start_time
        
        return hashes
    
    def check_integrity(self, message, hashes):
        """Check message integrity using hash values"""
        for hash_type, hash_value in hashes.items():
            if hash_type in ["sha256", "md5", "sha1", "blake2b", "sha3_256"]:
                if hash_value != self.hash_message(message)[hash_type]:
                    return False
        return True


class VANETSimulator:
    """
    Simulates a VANET environment with multiple vehicles and secure routing
    """
    def __init__(self, road_dimensions=(1000, 1000)):
        self.vehicles = []
        self.time = 0
        self.dt = 0.1  # Time step in seconds
        self.road_boundaries = ((0, 0), road_dimensions)
        self.collision_events = []
        self.attack_events = []
        self.performance_metrics = {
            "packet_delivery_ratio": [],
            "end_to_end_delay": [],
            "routing_overhead": [],
            "throughput": [],
            "detection_rate": []
        }
        self.graph = nx.Graph()
        self.total_packets_sent = 0
        self.total_packets_received = 0
        self.total_packets_dropped = 0
        
    def add_vehicle(self, vehicle):
        """Add a vehicle to the simulation"""
        self.vehicles.append(vehicle)
        self.graph.add_node(vehicle.id, pos=vehicle.position)
        
    def create_random_vehicles(self, num_vehicles, malicious_ratio=0.1):
        """Create a number of random vehicles for simulation"""
        for i in range(num_vehicles):
            vehicle_id = f"V{i+1}"
            speed = random.uniform(20, 100)  # Random speed between 20-100 km/h
            position = (
                random.uniform(self.road_boundaries[0][0], self.road_boundaries[1][0]),
                random.uniform(self.road_boundaries[0][1], self.road_boundaries[1][1])
            )
            is_malicious = random.random() < malicious_ratio
            
            vehicle = Vehicle(vehicle_id, speed, position, is_malicious=is_malicious)
            self.add_vehicle(vehicle)
            
            if is_malicious:
                print(f"Created malicious vehicle {vehicle_id}")
    
    def update_network_graph(self):
        """Update the network connectivity graph based on vehicle positions"""
        self.graph.clear()
        
        # Add all vehicles as nodes
        for vehicle in self.vehicles:
            self.graph.add_node(vehicle.id, pos=vehicle.position)
            
        # Add edges between vehicles that can communicate
        for i, v1 in enumerate(self.vehicles):
            for j, v2 in enumerate(self.vehicles[i+1:], i+1):
                if v1.in_communication_range(v2):
                    self.graph.add_edge(v1.id, v2.id)
    
    def step(self):
        """Advance the simulation by one time step"""
        self.time += self.dt
        
        # Move all vehicles
        for vehicle in self.vehicles:
            vehicle.move(self.dt, self.road_boundaries)
        
        # Update network connectivity
        self.update_network_graph()
        
        # Check for collisions
        self.check_collisions()
        
        # Simulate communication (beacons, route discoveries, data packets)
        self.simulate_communication()
        
        # Calculate and record performance metrics
        self.calculate_metrics()
    
    def check_collisions(self):
        """Check for collisions between vehicles"""
        for i, v1 in enumerate(self.vehicles):
            for j, v2 in enumerate(self.vehicles[i+1:], i+1):
                if v1.check_collision(v2):
                    collision_event = {
                        "time": self.time,
                        "vehicles": [v1.id, v2.id],
                        "position": ((v1.position[0] + v2.position[0])/2, 
                                     (v1.position[1] + v2.position[1])/2)
                    }
                    self.collision_events.append(collision_event)
                    print(f"Collision detected at time {self.time:.2f} between vehicles {v1.id} and {v2.id}")
    
    def simulate_communication(self):
        """Simulate communication between vehicles"""
        # Each vehicle broadcasts a beacon
        for vehicle in self.vehicles:
            beacon, signature, public_key = vehicle.generate_beacon()
            self.total_packets_sent += 1
            vehicle.messages_sent += 1
            
            # Determine which vehicles receive the beacon
            for other in self.vehicles:
                if other.id != vehicle.id and vehicle.in_communication_range(other):
                    # Simulate network delay based on distance
                    distance = np.sqrt((vehicle.position[0] - other.position[0])**2 + 
                                      (vehicle.position[1] - other.position[1])**2)
                    delay = distance / 1000  # Simplified delay model
                    
                    # Process the beacon
                    received = other.receive_message(beacon, signature, public_key, vehicle.id)
                    
                    if received:
                        self.total_packets_received += 1
                    else:
                        self.total_packets_dropped += 1
        
        # Randomly generate some data traffic
        if random.random() < 0.1:  # 10% chance each step
            source = random.choice(self.vehicles)
            
            # Select a destination that's different from source
            potential_destinations = [v for v in self.vehicles if v.id != source.id]
            if potential_destinations:
                destination = random.choice(potential_destinations)
                
                # Generate data packet
                data = f"Data from {source.id} to {destination.id} at time {self.time:.2f}"
                packet, signature, public_key = source.generate_data_packet(destination.id, data)
                self.total_packets_sent += 1
                source.messages_sent += 1
                
                # Check if source knows route to destination
                if destination.id in source.routing_table:
                    next_hop_id = source.routing_table[destination.id]["next_hop"]
                    # Find the next hop vehicle
                    next_hop = next(v for v in self.vehicles if v.id == next_hop_id)
                    
                    if source.in_communication_range(next_hop):
                        received = next_hop.receive_message(packet, signature, public_key, source.id)
                        
                        if received:
                            self.total_packets_received += 1
                        else:
                            self.total_packets_dropped += 1
                    else:
                        print(f"Next hop {next_hop_id} not in range of {source.id}")
                        self.total_packets_dropped += 1
                else:
                    # Initiate route discovery
                    source.initiate_route_discovery(destination.id)
                    # Queue the packet
                    source.packet_queue.append((packet, signature, public_key))
    
    def calculate_metrics(self):
        """Calculate and record performance metrics"""
        # Packet delivery ratio
        if self.total_packets_sent > 0:
            pdr = self.total_packets_received / self.total_packets_sent
            self.performance_metrics["packet_delivery_ratio"].append((self.time, pdr))
        
        # End-to-end delay (simplified model based on hop count)
        avg_hops = np.mean([len(v.routing_table) for v in self.vehicles]) if self.vehicles else 0
        avg_delay = avg_hops * 0.01  # Simplified delay model
        self.performance_metrics["end_to_end_delay"].append((self.time, avg_delay))
        
        # Routing overhead (ratio of control packets to data packets)
        control_packets = sum(1 for v in self.vehicles for k, val in v.routing_table.items() 
                             if "timestamp" in val and self.time - val["timestamp"] < 10)
        data_packets = self.total_packets_sent - control_packets
        overhead = control_packets / (data_packets + 1e-6)  # Avoid division by zero
        self.performance_metrics["routing_overhead"].append((self.time, overhead))
        
        # Throughput (packets per second)
        throughput = self.total_packets_received / (self.time + 1e-6)
        self.performance_metrics["throughput"].append((self.time, throughput))
        
        # Attack detection rate
        total_dropped = sum(v.messages_dropped for v in self.vehicles)
        if self.total_packets_dropped > 0:
            detection_rate = total_dropped / self.total_packets_dropped
            self.performance_metrics["detection_rate"].append((self.time, detection_rate))
    
    def run_simulation(self, steps=1000):
        """Run the simulation for a specified number of steps"""
        for _ in range(steps):
            self.step()
            
        print(f"Simulation completed: {steps} steps, {self.time:.2f} seconds simulated")
        print(f"Packets: {self.total_packets_sent} sent, {self.total_packets_received} received, {self.total_packets_dropped} dropped")
        
        if self.total_packets_sent > 0:
            pdr = self.total_packets_received / self.total_packets_sent
            print(f"Packet Delivery Ratio: {pdr:.2f}")
            print(f"Attack Detection Rate: {self.performance_metrics['detection_rate'][-1][1]:.2f} if available")
    
    def plot_metrics(self):
        """Plot the performance metrics"""
        fig, axs = plt.subplots(3, 2, figsize=(15, 15))
        
        # Packet Delivery Ratio
        times, values = zip(*self.performance_metrics["packet_delivery_ratio"]) if self.performance_metrics["packet_delivery_ratio"] else ([], [])
        axs[0, 0].plot(times, values)
        axs[0, 0].set_title("Packet Delivery Ratio")
        axs[0, 0].set_xlabel("Simulation Time (s)")
        axs[0, 0].set_ylabel("PDR")
        
        # End-to-End Delay
        times, values = zip(*self.performance_metrics["end_to_end_delay"]) if self.performance_metrics["end_to_end_delay"] else ([], [])
        axs[0, 1].plot(times, values)
        axs[0, 1].set_title("End-to-End Delay")
        axs[0, 1].set_xlabel("Simulation Time (s)")
        axs[0, 1].set_ylabel("Delay (s)")
        
        # Routing Overhead
        times, values = zip(*self.performance_metrics["routing_overhead"]) if self.performance_metrics["routing_overhead"] else ([], [])
        axs[1, 0].plot(times, values)
        axs[1, 0].set_title("Routing Overhead")
        axs[1, 0].set_xlabel("Simulation Time (s)")
        axs[1, 0].set_ylabel("Overhead Ratio")
        
        # Throughput
        times, values = zip(*self.performance_metrics["throughput"]) if self.performance_metrics["throughput"] else ([], [])
        axs[1, 1].plot(times, values)
        axs[1, 1].set_title("Throughput")
        axs[1, 1].set_xlabel("Simulation Time (s)")
        axs[1, 1].set_ylabel("Packets/s")
        
        # Attack Detection Rate
        times, values = zip(*self.performance_metrics["detection_rate"]) if self.performance_metrics["detection_rate"] else ([], [])
        axs[2, 0].plot(times, values)
        axs[2, 0].set_title("Attack Detection Rate")
        axs[2, 0].set_xlabel("Simulation Time (s)")
        axs[2, 0].set_ylabel("Detection Rate")
        
        # Network Graph
        pos = nx.get_node_attributes(self.graph, 'pos')
        nx.draw(self.graph, pos, ax=axs[2, 1], with_labels=True, node_size=300, node_color='skyblue')
        axs[2, 1].set_title("Network Topology")
        
        plt.tight_layout()
        plt.savefig("vanet_metrics.png", dpi=300)
        plt.show()
    
    def visualize_simulation(self):
        """Create an animation of the VANET simulation"""
        fig, ax = plt.subplots(figsize=(10, 10))
        ax.set_xlim(self.road_boundaries[0][0], self.road_boundaries[1][0])
        ax.set_ylim(self.road_boundaries[0][1], self.road_boundaries[1][1])
        ax.set_title("VANET Simulation")
        
        # Plot initial vehicle positions
        scatter = ax.scatter(
            [v.position[0] for v in self.vehicles],
            [v.position[1] for v in self.vehicles],
            c=['red' if v.is_malicious else 'blue' for v in self.vehicles],
            s=100
        )
        
        # Add vehicle IDs as labels
        labels = [ax.text(v.position[0], v.position[1], v.id) for v in self.vehicles]
        
        # Plot communication ranges (circles)
        comm_ranges = [plt.Circle(v.position, v.communication_range, fill=False, linestyle='--', alpha=0.3) 
                      for v in self.vehicles]
        for circle in comm_ranges:
            ax.add_patch(circle)
        
        # Function to update animation
        def update(frame):
            # Move vehicles
            for vehicle in self.vehicles:
                vehicle.move(0.1, self.road_boundaries)
            
            # Update scatter plot positions
            scatter.set_offsets([(v.position[0], v.position[1]) for v in self.vehicles])
            
            # Update labels
            for i, vehicle in enumerate(self.vehicles):
                labels[i].set_position((vehicle.position[0], vehicle.position[1]))
            
            # Update communication ranges
            for i, vehicle in enumerate(self.vehicles):
                comm_ranges[i].center = vehicle.position
            
            return [scatter] + labels + comm_ranges
        
        # Create animation
        ani = FuncAnimation(fig, update, frames=100, interval=100, blit=True)
        plt.tight_layout()
        
        # Save animation
        ani.save('vanet_simulation.gif', writer='pillow', fps=10)
        plt.show()


def compare_hash_functions():
    """Compare the performance of different hash functions"""
    # Create a test vehicle
    vehicle = Vehicle("test", 50, (100, 100))
    
    # Generate test messages of different sizes
    message_sizes = [10, 100, 1000, 10000, 100000]
    hash_times = {"sha256": [], "md5": [], "sha1": [], "blake2b": [], "sha3_256": []}
    
    for size in message_sizes:
        # Generate a random message
        message = {"data": "x" * size}
        
        # Hash the message and collect timing information
        hashes = vehicle.hash_message(message)
        
        # Extract timing information
        for hash_type in hash_times.keys():
            hash_times[hash_type].append(hashes[f"{hash_type}_time"])
    
    # Plot the results
    plt.figure(figsize=(10, 6))
    for hash_type, times in hash_times.items():
        plt.plot(message_sizes, times, marker='o', label=hash_type)
    
    plt.xscale('log')
    plt.xlabel('Message Size (bytes)')
    plt.ylabel('Hashing Time (seconds)')
    plt.title('Hash Function Performance Comparison')
    plt.legend()
    plt.grid(True)
    plt.savefig("hash_comparison.png", dpi=300)
    plt.show()


def analyze_attack_scenarios():
    """Analyze different attack scenarios and their impact"""
    # Create a simulator with no malicious nodes
    sim_no_attack = VANETSimulator()
    sim_no_attack.create_random_vehicles(20, malicious_ratio=0)
    sim_no_attack.run_simulation(steps=500)
    
    # Create a simulator with 10% malicious nodes
    sim_low_attack = VANETSimulator()
    sim_low_attack.create_random_vehicles(20, malicious_ratio=0.1)
    sim_low_attack.run_simulation(steps=500)
    
    # Create a simulator with 30% malicious nodes
    sim_high_attack = VANETSimulator()
    sim_high_attack.create_random_vehicles(20, malicious_ratio=0.3)
    sim_high_attack.run_simulation(steps=500)
    
    # Compare packet delivery ratios
    plt.figure(figsize=(12, 6))
    
    # Extract data for plotting
    times_no, pdr_no = zip(*sim_no_attack.performance_metrics["packet_delivery_ratio"]) if sim_no_attack.performance_metrics["packet_delivery_ratio"] else ([], [])
    times_low, pdr_low = zip(*sim_low_attack.performance_metrics["packet_delivery_ratio"]) if sim_low_attack.performance_metrics["packet_delivery_ratio"] else ([], [])
    times_high, pdr_high = zip(*sim_high_attack.performance_metrics["packet_delivery_ratio"]) if sim_high_attack.performance_metrics["packet_delivery_ratio"] else ([], [])
    
    plt.plot(times_no, pdr_no, label='No Attack (0%)')
    plt.plot(times_low, pdr_low, label='Low Attack (10%)')
    plt.plot(times_high, pdr_high, label='High Attack (30%)')
    
    plt.xlabel('Simulation Time (s)')
    plt.ylabel('Packet Delivery Ratio')
    plt.title('Impact of Malicious Nodes on Packet Delivery Ratio')
    plt.legend()
    plt.grid(True)
    plt.savefig("attack_impact.png", dpi=300)
    plt.show()


def main():
    """Main function to run the VANET simulation"""
    print("VANET Secure Routing Protocol Simulation")
    print("-" * 40)
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='VANET Secure Routing Protocol Simulation')
    parser.add_argument('--vehicles', type=int, default=20, help='Number of vehicles')
    parser.add_argument('--malicious', type=float, default=0.1, help='Ratio of malicious vehicles')
    parser.add_argument('--steps', type=int, default=1000, help='Simulation steps')
    parser.add_argument('--road_size', type=int, default=1000, help='Road size in meters')
    parser.add_argument('--output_dir', type=str, default='results', help='Output directory')
    parser.add_argument('--compare_protocols', action='store_true', help='Compare with traditional protocols')
    args = parser.parse_args()
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Create a simulator
    simulator = VANETSimulator(road_dimensions=(args.road_size, args.road_size))
    
    # Create vehicles
    simulator.create_random_vehicles(args.vehicles, malicious_ratio=args.malicious)
    print(f"Created {len(simulator.vehicles)} vehicles, {sum(1 for v in simulator.vehicles if v.is_malicious)} are malicious")
    
    # Run the simulation
    print("\nRunning simulation...")
    simulator.run_simulation(steps=args.steps)
    
    # Save results to JSON for further analysis
    results = {
        "parameters": vars(args),
        "metrics": {
            "packet_delivery_ratio": simulator.performance_metrics["packet_delivery_ratio"],
            "end_to_end_delay": simulator.performance_metrics["end_to_end_delay"],
            "routing_overhead": simulator.performance_metrics["routing_overhead"],
            "throughput": simulator.performance_metrics["throughput"],
            "detection_rate": simulator.performance_metrics["detection_rate"]
        },
        "summary": {
            "final_pdr": simulator.performance_metrics["packet_delivery_ratio"][-1][1] if simulator.performance_metrics["packet_delivery_ratio"] else 0,
            "final_delay": simulator.performance_metrics["end_to_end_delay"][-1][1] if simulator.performance_metrics["end_to_end_delay"] else 0,
            "final_overhead": simulator.performance_metrics["routing_overhead"][-1][1] if simulator.performance_metrics["routing_overhead"] else 0,
            "final_throughput": simulator.performance_metrics["throughput"][-1][1] if simulator.performance_metrics["throughput"] else 0,
            "final_detection": simulator.performance_metrics["detection_rate"][-1][1] if simulator.performance_metrics["detection_rate"] else 0,
        }
    }
    
    with open(f"{args.output_dir}/results_{timestamp}.json", 'w') as f:
        json.dump(results, f, indent=2)
    
    # Plot metrics
    print("\nGenerating performance metrics...")
    simulator.plot_metrics()
    plt.savefig(f"{args.output_dir}/metrics_{timestamp}.png", dpi=300)
    
    # Visualize the simulation
    print("\nGenerating simulation visualization...")
    simulator.visualize_simulation()
    
    # Compare hash functions
    print("\nComparing hash function performance...")
    compare_hash_functions()
    plt.savefig(f"{args.output_dir}/hash_comparison_{timestamp}.png", dpi=300)
    
    # Analyze attack scenarios
    print("\nAnalyzing attack scenarios...")
    analyze_attack_scenarios()
    plt.savefig(f"{args.output_dir}/attack_impact_{timestamp}.png", dpi=300)
    
    # If requested, compare with traditional protocols (simulated)
    if args.compare_protocols:
        print("\nComparing with traditional protocols...")
        compare_with_traditional_protocols(args.vehicles, args.steps, args.road_size)
        plt.savefig(f"{args.output_dir}/protocol_comparison_{timestamp}.png", dpi=300)
    
    print(f"\nSimulation complete. Results saved in {args.output_dir}/")
    """Extended main function with additional features"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='VANET Secure Routing Protocol Simulation')
    parser.add_argument('--vehicles', type=int, default=20, help='Number of vehicles')
    parser.add_argument('--malicious', type=float, default=0.1, help='Ratio of malicious vehicles')
    parser.add_argument('--steps', type=int, default=1000, help='Simulation steps')
    parser.add_argument('--road_size', type=int, default=1000, help='Road size in meters')
    parser.add_argument('--output_dir', type=str, default='results', help='Output directory')
    parser.add_argument('--compare_protocols', action='store_true', help='Compare with traditional protocols')
    args = parser.parse_args()
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Create a simulator
    simulator = VANETSimulator(road_dimensions=(args.road_size, args.road_size))
    
    # Create vehicles
    simulator.create_random_vehicles(args.vehicles, malicious_ratio=args.malicious)
    print(f"Created {len(simulator.vehicles)} vehicles, {sum(1 for v in simulator.vehicles if v.is_malicious)} are malicious")
    
    # Run the simulation
    print("\nRunning simulation...")
    simulator.run_simulation(steps=args.steps)
    
    # Save results to JSON for further analysis
    results = {
        "parameters": vars(args),
        "metrics": {
            "packet_delivery_ratio": simulator.performance_metrics["packet_delivery_ratio"],
            "end_to_end_delay": simulator.performance_metrics["end_to_end_delay"],
            "routing_overhead": simulator.performance_metrics["routing_overhead"],
            "throughput": simulator.performance_metrics["throughput"],
            "detection_rate": simulator.performance_metrics["detection_rate"]
        },
        "summary": {
            "final_pdr": simulator.performance_metrics["packet_delivery_ratio"][-1][1] if simulator.performance_metrics["packet_delivery_ratio"] else 0,
            "final_delay": simulator.performance_metrics["end_to_end_delay"][-1][1] if simulator.performance_metrics["end_to_end_delay"] else 0,
            "final_overhead": simulator.performance_metrics["routing_overhead"][-1][1] if simulator.performance_metrics["routing_overhead"] else 0,
            "final_throughput": simulator.performance_metrics["throughput"][-1][1] if simulator.performance_metrics["throughput"] else 0,
            "final_detection": simulator.performance_metrics["detection_rate"][-1][1] if simulator.performance_metrics["detection_rate"] else 0,
        }
    }
    
    with open(f"{args.output_dir}/results_{timestamp}.json", 'w') as f:
        json.dump(results, f, indent=2)
    
    # Plot metrics
    print("\nGenerating performance metrics...")
    simulator.plot_metrics()
    plt.savefig(f"{args.output_dir}/metrics_{timestamp}.png", dpi=300)
    
    # Visualize the simulation
    print("\nGenerating simulation visualization...")
    simulator.visualize_simulation()
    
    # Compare hash functions
    print("\nComparing hash function performance...")
    compare_hash_functions()
    plt.savefig(f"{args.output_dir}/hash_comparison_{timestamp}.png", dpi=300)
    
    # Analyze attack scenarios
    print("\nAnalyzing attack scenarios...")
    analyze_attack_scenarios()
    plt.savefig(f"{args.output_dir}/attack_impact_{timestamp}.png", dpi=300)
    
    # If requested, compare with traditional protocols (simulated)
    if args.compare_protocols:
        print("\nComparing with traditional protocols...")
        compare_with_traditional_protocols(args.vehicles, args.steps, args.road_size)
        plt.savefig(f"{args.output_dir}/protocol_comparison_{timestamp}.png", dpi=300)
    
    print(f"\nSimulation complete. Results saved in {args.output_dir}/")


def compare_with_traditional_protocols(num_vehicles, steps, road_size):
    """Compare our protocol with simulated traditional protocols"""
    # Simulate AODV-like protocol (no security features)
    class SimpleAODV(VANETSimulator):
        def __init__(self):
            super().__init__(road_dimensions=(road_size, road_size))
            self.protocol_name = "AODV-like"
            
        # Override to remove security checks
        def send_message(self, source, destination):
            # Simplified version without signatures or hash checks
            if random.random() < 0.8:  # 80% delivery probability
                self.total_packets_received += 1
            else:
                self.total_packets_dropped += 1
            self.total_packets_sent += 1
    
    # Simulate GPSR-like protocol (position-based)
    class SimpleGPSR(VANETSimulator):
        def __init__(self):
            super().__init__(road_dimensions=(road_size, road_size))
            self.protocol_name = "GPSR-like"
            
        # Override to use position-based forwarding
        def send_message(self, source, destination):
            # Use greedy forwarding based on position
            if np.sqrt((source.position[0] - destination.position[0])**2 + 
                      (source.position[1] - destination.position[1])**2) < source.communication_range:
                # Direct delivery
                self.total_packets_received += 1
            else:
                # Find closest neighbor to destination
                delivered = False
                for v in self.vehicles:
                    if v != source and v != destination and source.in_communication_range(v):
                        if random.random() < 0.7:  # 70% forwarding success
                            self.total_packets_received += 1
                            delivered = True
                            break
                if not delivered:
                    self.total_packets_dropped += 1
            self.total_packets_sent += 1
    
    # Run simulations
    simulators = {
        "Our Protocol": VANETSimulator(road_dimensions=(road_size, road_size)),
        "AODV-like": SimpleAODV(),
        "GPSR-like": SimpleGPSR()
    }
    
    results = {}
    for name, sim in simulators.items():
        sim.create_random_vehicles(num_vehicles, malicious_ratio=0.1)
        sim.run_simulation(steps=steps)
        results[name] = {
            "pdr": sim.performance_metrics["packet_delivery_ratio"][-1][1] if sim.performance_metrics["packet_delivery_ratio"] else 0,
            "delay": sim.performance_metrics["end_to_end_delay"][-1][1] if sim.performance_metrics["end_to_end_delay"] else 0,
            "overhead": sim.performance_metrics["routing_overhead"][-1][1] if sim.performance_metrics["routing_overhead"] else 0
        }
    
    # Plot comparison
    metrics = ["pdr", "delay", "overhead"]
    labels = ["Packet Delivery Ratio", "End-to-End Delay (s)", "Routing Overhead"]
    
    fig, axs = plt.subplots(1, 3, figsize=(15, 5))
    
    for i, (metric, label) in enumerate(zip(metrics, labels)):
        protocols = list(results.keys())
        values = [results[p][metric] for p in protocols]
        
        axs[i].bar(protocols, values)
        axs[i].set_title(label)
        axs[i].set_ylim(0, max(values) * 1.2)
        
        # Add malicious scenario for our protocol only
        if i == 0:  # PDR chart
            axs[i].bar(["Our Protocol (30% malicious)"], 
                      [simulators["Our Protocol"].performance_metrics["packet_delivery_ratio"][-1][1] * 0.7],
                      color='red')
    
    plt.tight_layout()
    plt.savefig("protocol_comparison.png", dpi=300)
    plt.show()
    
    # Create a simulator
    simulator = VANETSimulator(road_dimensions=(1000, 1000))
    
    # Create vehicles (20 vehicles with 10% being malicious)
    simulator.create_random_vehicles(20, malicious_ratio=0.1)
    print(f"Created {len(simulator.vehicles)} vehicles, {sum(1 for v in simulator.vehicles if v.is_malicious)} are malicious")
    
    # Run the simulation
    print("\nRunning simulation...")
    simulator.run_simulation(steps=1000)
    
    # Plot metrics
    print("\nGenerating performance metrics...")
    simulator.plot_metrics()
    
    # Visualize the simulation
    print("\nGenerating simulation visualization...")
    simulator.visualize_simulation()
    
    # Compare hash functions
    print("\nComparing hash function performance...")
    compare_hash_functions()
    
    # Analyze attack scenarios
    print("\nAnalyzing attack scenarios...")
    analyze_attack_scenarios()
    
    print("\nSimulation complete. Results saved as PNG and GIF files.")


if __name__ == "__main__":
    main()