#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fail2ban Telegram Notification Script

Send Fail2ban ban/unban notifications to Telegram, including IP geolocation
information.
"""

import sys
import os
import json
import logging
import configparser
import requests
from datetime import datetime
from typing import Optional, Dict, Any

# Log configuration
LOG_FILE = '/var/log/fail2ban-telegram.log'
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stderr)
    ]
)
logger = logging.getLogger(__name__)

# Config file path
CONFIG_FILE = '/etc/fail2ban/telegram.conf'

class TelegramNotifier:
    """Telegram notification helper"""
    
    def __init__(self, config_file: str = CONFIG_FILE):
        """Initialize notifier and load configuration"""
        self.config = configparser.ConfigParser()
        self.config.read(config_file)
        
        # Read configuration
        self.bot_token = self.config.get('telegram', 'bot_token', fallback='')
        self.chat_id = self.config.get('telegram', 'chat_id', fallback='')
        self.ipinfo_token = self.config.get('ipinfo', 'token', fallback='')
        self.enable_unban = self.config.getboolean('settings', 'enable_unban', fallback=True)
        self.server_name = self.config.get('settings', 'server_name', fallback='Server')
        self.enable_links = self.config.getboolean('settings', 'enable_links', fallback=True)
        
        # Validate required configuration
        if not self.bot_token or not self.chat_id:
            logger.error("Telegram bot token or chat ID is not configured")
            sys.exit(1)
    
    def get_ip_info(self, ip: str) -> Optional[Dict[str, Any]]:
        """Fetch IP information from ipinfo.io"""
        try:
            url = f"https://ipinfo.io/{ip}/json"
            headers = {
                'User-Agent': 'Fail2ban-Telegram-Notifier/1.0',
                'Accept': 'application/json'
            }
            if self.ipinfo_token:
                headers['Authorization'] = f'Bearer {self.ipinfo_token}'
            
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            # Ensure we always have an IP field
            if 'ip' not in data:
                data['ip'] = ip
            
            return data
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout while fetching IP information: {ip}")
            return None
        except requests.exceptions.RequestException as e:
            logger.warning(f"Failed to fetch IP information: {e}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse IP information JSON: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error while handling IP information: {e}")
            return None
    
    def format_message(self, event_type: str, ip: str, jail: str = '', 
                      bantime: str = '', ip_info: Optional[Dict[str, Any]] = None) -> str:
        """Format Telegram message text"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        if event_type == 'ban':
            emoji = '🚫'
            title = f"{emoji} *Fail2ban just banned {ip}*"
            status_emoji = '✅'
            status_text = "success"
        elif event_type == 'unban':
            emoji = '✅'
            title = f"{emoji} *Fail2ban just unbanned {ip}*"
            status_emoji = '🔓'
            status_text = "unbanned"
        else:
            emoji = 'ℹ️'
            title = f"{emoji} *Fail2ban Notification*"
            status_emoji = 'ℹ️'
            status_text = "info"
        
        # Build header section
        message_parts = [
            title,
            "",
            f"Status: {status_text}",
        ]
        
        # IP geolocation information
        if ip_info:
            # Extract IP information
            country_code = ip_info.get('country', '')
            country_name = ip_info.get('country_name', '')
            if not country_name and country_code:
                # 如果没有 country_name，尝试使用 country 代码
                country_name = country_code
            
            region = ip_info.get('region', '')
            city = ip_info.get('city', '')
            postal = ip_info.get('postal', '')
            loc = ip_info.get('loc', '')
            timezone = ip_info.get('timezone', '')
            org = ip_info.get('org', '')
            
            # Parse AS / ISP / organization info
            asn = ''
            isp = ''
            organization = ''
            
            if org:
                # org may look like one of:
                # - "AS12345 Organization Name"
                # - "AS12345 ISP Name / Organization Name"
                # - "AS12345 ISP Name, Organization Name"
                parts = org.split(' ', 1)
                if len(parts) == 2:
                    asn = parts[0]  # AS 号码
                    remaining = parts[1]
                    
                    # 检查是否有斜杠分隔 ISP 和组织
                    if ' / ' in remaining:
                        org_parts = remaining.split(' / ', 1)
                        isp = org_parts[0].strip()
                        organization = org_parts[1].strip()
                    elif ', ' in remaining:
                        # Some formats use comma as separator
                        org_parts = remaining.split(', ', 1)
                        isp = org_parts[0].strip()
                        organization = org_parts[1].strip()
                    else:
                        # No extra separator, treat as ISP name
                        isp = remaining.strip()
                        organization = remaining.strip()
                else:
                    # No AS number, treat whole string as organization
                    isp = org
                    organization = org
            
            # Build formatted message in a readable order
            message_parts.append("")
            
            # Country
            if country_name:
                if country_code:
                    message_parts.append(f"Country: {country_name} ({country_code})")
                else:
                    message_parts.append(f"Country: {country_name}")
            elif country_code:
                message_parts.append(f"Country: {country_code}")
            
            # Region / state
            if region:
                # Try to extract region code if present in parentheses
                if ' (' in region:
                    region_parts = region.split(' (', 1)
                    region_name = region_parts[0]
                    region_code = region_parts[1].rstrip(')')
                    message_parts.append(f"Region: {region_name} ({region_code})")
                else:
                    message_parts.append(f"Region: {region}")
            
            # City
            if city:
                message_parts.append(f"City: {city}")
            
            # ZIP Code
            message_parts.append(f"ZIP Code: {postal if postal else ''}")
            
            # Coordinates
            if loc:
                coords = loc.split(',')
                if len(coords) == 2:
                    lat = coords[0].strip()
                    lon = coords[1].strip()
                    message_parts.append(f"Coordinates: ({lat}, {lon})")
                    
                    # Add map links (if enabled)
                    if self.enable_links:
                        message_parts.append(f"  📍 [Google Maps](https://www.google.com/maps?q={lat},{lon}) | [OSM](https://www.openstreetmap.org/?mlat={lat}&mlon={lon})")
            
            # Timezone
            if timezone:
                message_parts.append(f"Timezone: {timezone}")
            
            message_parts.append("")
            
            # ISP
            if isp:
                message_parts.append(f"ISP: {isp}")
            
            # Organization
            if organization and organization != isp:
                message_parts.append(f"Organization: {organization}")
            
            # AS
            if asn:
                message_parts.append(f"AS: {asn}")
            
            message_parts.append("")
        else:
            message_parts.append("")
            message_parts.append("⚠️ Unable to fetch location information")
            message_parts.append("")
        
        # IP 地址（始終顯示）
        message_parts.append(f"IP Address: {ip}")
        
        # 額外資訊（如果有的話）
        if jail or bantime:
            message_parts.append("")
            if jail:
                message_parts.append(f"Service/Jail: {jail}")
            if bantime:
                message_parts.append(f"Ban Duration: {bantime}")
        
        # 服務器和時間資訊（可選，放在底部作為補充資訊）
        message_parts.append("")
        if self.server_name and self.server_name != 'Server':
            message_parts.append(f"Server: {self.server_name}")
        message_parts.append(f"Time: {timestamp}")
        
        # 添加额外的实用链接（如果启用）
        if self.enable_links:
            message_parts.append("")
            message_parts.append("🔗 [IP Lookup](https://ipinfo.io/{}) | [AbuseIPDB](https://www.abuseipdb.com/check/{}) | [VirusTotal](https://www.virustotal.com/gui/ip-address/{})".format(ip, ip, ip))
        
        return "\n".join(message_parts)
    
    def send_message(self, message: str) -> bool:
        """Send a message to Telegram"""
        try:
            url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
            payload = {
                'chat_id': self.chat_id,
                'text': message,
                'parse_mode': 'Markdown',
                'disable_web_page_preview': True
            }
            
            response = requests.post(url, json=payload, timeout=10)
            response.raise_for_status()
            logger.info("Message sent successfully")
            return True
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to send Telegram message: {e}")
            if hasattr(e.response, 'text'):
                logger.error(f"Response content: {e.response.text}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error while sending Telegram message: {e}")
            return False
    
    def handle_ban(self, ip: str, jail: str = '', bantime: str = ''):
        """Handle a ban event"""
        logger.info(f"Handling ban event: IP={ip}, Jail={jail}")
        
        # Fetch IP info
        ip_info = self.get_ip_info(ip)
        
        # Format message
        message = self.format_message('ban', ip, jail, bantime, ip_info)
        
        # Send message
        self.send_message(message)
    
    def handle_unban(self, ip: str, jail: str = ''):
        """Handle an unban event"""
        if not self.enable_unban:
            logger.info("Unban notifications are disabled, skipping")
            return
        
        logger.info(f"Handling unban event: IP={ip}, Jail={jail}")
        
        # Fetch IP info
        ip_info = self.get_ip_info(ip)
        
        # Format message
        message = self.format_message('unban', ip, jail, '', ip_info)
        
        # Send message
        self.send_message(message)


def main():
    """CLI entry point"""
    if len(sys.argv) < 2:
        logger.error("Usage: fail2ban-telegram.py <action> [ip] [jail] [bantime]")
        sys.exit(1)
    
    action = sys.argv[1]
    notifier = TelegramNotifier()
    
    if action == 'ban':
        if len(sys.argv) < 3:
            logger.error("ban action requires an IP address")
            sys.exit(1)
        ip = sys.argv[2]
        jail = sys.argv[3] if len(sys.argv) > 3 else ''
        bantime = sys.argv[4] if len(sys.argv) > 4 else ''
        notifier.handle_ban(ip, jail, bantime)
    
    elif action == 'unban':
        if len(sys.argv) < 3:
            logger.error("unban action requires an IP address")
            sys.exit(1)
        ip = sys.argv[2]
        jail = sys.argv[3] if len(sys.argv) > 3 else ''
        notifier.handle_unban(ip, jail)
    
    elif action == 'start':
        logger.info("Fail2ban Telegram notification service started")
        message = (
            "🚀 *Fail2ban Telegram notification service started*\n\n"
            f"*Server:* {notifier.server_name}\n"
            f"*Time:* `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`"
        )
        notifier.send_message(message)
    
    elif action == 'stop':
        logger.info("Fail2ban Telegram notification service stopped")
        message = (
            "🛑 *Fail2ban Telegram notification service stopped*\n\n"
            f"*Server:* {notifier.server_name}\n"
            f"*Time:* `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`"
        )
        notifier.send_message(message)
    
    elif action == 'check':
        # Check configuration and connectivity
        logger.info("Checking Telegram bot connectivity...")
        try:
            url = f"https://api.telegram.org/bot{notifier.bot_token}/getMe"
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            bot_info = response.json()
            if bot_info.get('ok'):
                logger.info(f"Bot connection OK: @{bot_info['result']['username']}")
            else:
                logger.error("Bot connection failed")
        except Exception as e:
            logger.error(f"Check failed: {e}")
    
    else:
        logger.error(f"Unknown action: {action}")
        sys.exit(1)


if __name__ == '__main__':
    main()

