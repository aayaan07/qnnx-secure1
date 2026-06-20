from sqlalchemy.orm import Session as DBSession

from app.repositories.tunnel_state_repo import TunnelStateRepository
from app.repositories.traffic_stat_repo import TrafficStatRepository
from app.repositories.system_metric_repo import SystemMetricRepository
from app.repositories.security_alert_repo import SecurityAlertRepository
from app.repositories.client_repo import ClientRepository
from app.repositories.user_activity_repo import UserActivityRepository
from app.repositories.network_activity_repo import NetworkActivityRepository
from app.repositories.process_metric_repo import ProcessMetricRepository
from app.repositories.ip_history_repo import IPHistoryRepository
from app.repositories.vpn_event_repo import VPNEventRepository

class MonitoringService:
    def __init__(self):
        self.tunnel_repo = TunnelStateRepository()
        self.traffic_repo = TrafficStatRepository()
        self.metrics_repo = SystemMetricRepository()
        self.alert_repo = SecurityAlertRepository()
        self.client_repo = ClientRepository()
        self.user_act_repo = UserActivityRepository()
        self.net_act_repo = NetworkActivityRepository()
        self.process_repo = ProcessMetricRepository()
        self.ip_repo = IPHistoryRepository()
        self.vpn_evt_repo = VPNEventRepository()

    def get_realtime_state(self, db: DBSession) -> dict:
        """
        Aggregates live information from all database modules and returns a
        complete state summary containing active tunnels, health metrics,
        alerts, running processes, open network sockets, and a unified Event Timeline.
        """
        # 1. Gather Tunnel States & Active Connections
        all_tunnels = self.tunnel_repo.get_all(db)
        active_tunnels = [t for t in all_tunnels if t.status == "ACTIVE"]
        
        tunnels_detail = []
        public_ips = set()
        
        for t in active_tunnels:
            # Look up client info to get its identifier
            from app.models.session import Session as SessionModel
            session_row = db.query(SessionModel).filter(SessionModel.id == t.session_id).first()
            client_identifier = "Unknown"
            if session_row:
                client = self.client_repo.get_by_id(db, session_row.client_id)
                if client:
                    client_identifier = client.client_identifier
            
            tunnels_detail.append({
                "session_id": str(t.session_id),
                "client_identifier": client_identifier,
                "remote_ip": t.remote_ip,
                "remote_port": t.remote_port,
                "status": t.status,
                "last_heartbeat": t.last_heartbeat.isoformat() if t.last_heartbeat else None,
                "established_at": t.established_at.isoformat() if t.established_at else None
            })
            if t.remote_ip:
                public_ips.add(t.remote_ip)

        # Tunnel Status Counts
        status_counts = {
            "ACTIVE": 0,
            "DEGRADED": 0,
            "DISCONNECTED": 0,
            "CONNECTING": 0
        }
        for t in all_tunnels:
            if t.status in status_counts:
                status_counts[t.status] += 1

        # 2. System Health - Aggregate Agent Metrics
        all_metrics = self.metrics_repo.get_all(db)
        latest_client_metrics = {}
        for metric in all_metrics:
            client_id = metric.client_identifier
            if client_id not in latest_client_metrics:
                latest_client_metrics[client_id] = metric
            elif metric.recorded_at > latest_client_metrics[client_id].recorded_at:
                latest_client_metrics[client_id] = metric

        num_reporting = len(latest_client_metrics)
        avg_cpu = 0.0
        avg_ram = 0.0
        avg_disk = 0.0
        
        if num_reporting > 0:
            total_cpu = sum(m.cpu_usage for m in latest_client_metrics.values())
            total_ram = sum(m.ram_usage for m in latest_client_metrics.values())
            total_disk = sum(m.disk_usage for m in latest_client_metrics.values())
            
            avg_cpu = round(total_cpu / num_reporting, 2)
            avg_ram = round(total_ram / num_reporting, 2)
            avg_disk = round(total_disk / num_reporting, 2)

        # 3. Active Processes & Network Sockets
        # Get latest active processes for all clients
        active_processes = []
        for client_id in latest_client_metrics.keys():
            procs = self.process_repo.get_latest_for_client(db, client_id, limit=5)
            for p in procs:
                active_processes.append({
                    "client_identifier": p.client_identifier,
                    "pid": p.pid,
                    "name": p.name,
                    "cpu_percent": p.cpu_percent
                })

        # Get latest established socket connections
        active_sockets = []
        for client_id in latest_client_metrics.keys():
            conns = self.net_act_repo.get_latest_for_client(db, client_id, limit=5)
            for c in conns:
                active_sockets.append({
                    "client_identifier": c.client_identifier,
                    "pid": c.pid,
                    "local_port": c.local_port,
                    "remote_ip": c.remote_ip,
                    "remote_port": c.remote_port
                })

        # 4. Aggregated Traffic Statistics
        traffic_records = self.traffic_repo.get_all(db)
        total_bytes_sent = sum(tr.bytes_sent for tr in traffic_records)
        total_bytes_received = sum(tr.bytes_received for tr in traffic_records)
        total_packets_sent = sum(tr.packets_sent for tr in traffic_records)
        total_packets_received = sum(tr.packets_received for tr in traffic_records)

        # 5. Unresolved Security Alerts
        open_alerts = self.alert_repo.get_open_alerts(db)
        alerts_list = []
        for alert in open_alerts:
            alerts_list.append({
                "alert_id": str(alert.id),
                "alert_type": alert.alert_type,
                "severity": alert.severity,
                "description": alert.description,
                "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
                "status": alert.status
            })

        # 6. Unified Event Timeline (Chronological Aggregator)
        timeline_events = []

        # Ingest VPN Client events
        vpn_events = self.vpn_evt_repo.get_all(db)
        for ev in vpn_events:
            timeline_events.append({
                "timestamp": ev.recorded_at.isoformat(),
                "event_type": "VPN_EVENT",
                "client_identifier": ev.client_identifier,
                "severity": "INFO" if ev.event_type == "TUNNEL_UP" else "WARNING",
                "description": f"VPN Client state changed to {ev.event_type} (Gateway: {ev.ip_address or 'N/A'})"
            })

        # Ingest Windows User Activity events
        user_acts = self.user_act_repo.get_all(db)
        for act in user_acts:
            action = "Logged In" if act.event_id == 4624 else "Logged Out"
            timeline_events.append({
                "timestamp": act.recorded_at.isoformat(),
                "event_type": "USER_EVENT",
                "client_identifier": act.client_identifier,
                "severity": "INFO",
                "description": f"User successfully {action} (Windows Event {act.event_id})"
            })

        # Ingest Public IP History events
        ip_histories = self.ip_repo.get_all(db)
        for ip_rec in ip_histories:
            timeline_events.append({
                "timestamp": ip_rec.recorded_at.isoformat(),
                "event_type": "IP_EVENT",
                "client_identifier": ip_rec.client_identifier,
                "severity": "INFO",
                "description": f"Public IP Address logged: {ip_rec.ip_address}"
            })

        # Ingest Security Alerts (both open and resolved)
        all_alerts = self.alert_repo.get_all(db)
        for alert in all_alerts:
            timeline_events.append({
                "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
                "event_type": "SECURITY_ALERT",
                "client_identifier": "System",  # Aggregated alert
                "severity": alert.severity,
                "description": f"[{alert.status}] Threat alert: {alert.description}"
            })

        # Sort all timeline events chronologically (newest first)
        timeline_events.sort(key=lambda x: x["timestamp"] or "", reverse=True)
        recent_timeline = timeline_events[:20]  # limit to top 20 events

        # Assemble real-time snapshot
        return {
            "active_clients": len(active_tunnels),
            "active_sessions": len(active_tunnels),
            "current_public_ips": list(public_ips),
            "tunnels": tunnels_detail,
            "tunnel_status_summary": status_counts,
            "system_health": {
                "active_agents": num_reporting,
                "average_cpu_usage_pct": avg_cpu,
                "average_ram_usage_pct": avg_ram,
                "average_disk_usage_pct": avg_disk
            },
            "active_processes": active_processes,
            "active_sockets": active_sockets,
            "current_alerts": alerts_list,
            "event_timeline": recent_timeline,
            "traffic_statistics": {
                "total_bytes_sent": total_bytes_sent,
                "total_bytes_received": total_bytes_received,
                "total_packets_sent": total_packets_sent,
                "total_packets_received": total_packets_received
            }
        }
