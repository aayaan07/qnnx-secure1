from sqlalchemy.orm import Session as DBSession

from app.repositories.tunnel_state_repo import TunnelStateRepository
from app.repositories.traffic_stat_repo import TrafficStatRepository
from app.repositories.system_metric_repo import SystemMetricRepository
from app.repositories.security_alert_repo import SecurityAlertRepository
from app.repositories.client_repo import ClientRepository

class MonitoringService:
    def __init__(self):
        self.tunnel_repo = TunnelStateRepository()
        self.traffic_repo = TrafficStatRepository()
        self.metrics_repo = SystemMetricRepository()
        self.alert_repo = SecurityAlertRepository()
        self.client_repo = ClientRepository()

    def get_realtime_state(self, db: DBSession) -> dict:
        """
        Aggregates live information from all database modules and returning a
        state summary containing tunnels, health metrics, alerts, and bandwidth stats.
        """
        # 1. Gather Tunnel States & Active Connections
        all_tunnels = self.tunnel_repo.get_all(db)
        active_tunnels = [t for t in all_tunnels if t.status == "ACTIVE"]
        
        # Build active tunnels details list
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
        # We find unique reporting clients and take their latest recorded metrics
        all_metrics = self.metrics_repo.get_all(db)
        latest_client_metrics = {}
        for metric in all_metrics:
            client_id = metric.client_identifier
            # Since metrics are ordered by record time default, or we can compare,
            # let's update if recorded_at is newer or not yet stored.
            if client_id not in latest_client_metrics:
                latest_client_metrics[client_id] = metric
            elif metric.recorded_at > latest_client_metrics[client_id].recorded_at:
                latest_client_metrics[client_id] = metric

        # Calculate averages of unique client metrics
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

        # 3. Aggregated Traffic Statistics
        traffic_records = self.traffic_repo.get_all(db)
        total_bytes_sent = sum(tr.bytes_sent for tr in traffic_records)
        total_bytes_received = sum(tr.bytes_received for tr in traffic_records)
        total_packets_sent = sum(tr.packets_sent for tr in traffic_records)
        total_packets_received = sum(tr.packets_received for tr in traffic_records)

        # 4. Unresolved Security Alerts
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
            "current_alerts": alerts_list,
            "traffic_statistics": {
                "total_bytes_sent": total_bytes_sent,
                "total_bytes_received": total_bytes_received,
                "total_packets_sent": total_packets_sent,
                "total_packets_received": total_packets_received
            }
        }
