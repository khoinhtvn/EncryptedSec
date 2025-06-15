#!/bin/bash

cd /sec/zeek

case "$1" in
    start)
        INTERFACE=${2:-$(grep ZEEK_INTERFACE .env 2>/dev/null | cut -d'=' -f2 || echo "eth0")}
        echo "Starting Zeek on interface: $INTERFACE"
        
        # Update .env file with interface
        if [ -n "$2" ]; then
            echo "ZEEK_INTERFACE=$2" > .env
        elif [ ! -f .env ]; then
            echo "ZEEK_INTERFACE=eth0" > .env
        fi
        
        # Check if interface exists
        if ! ip link show $INTERFACE > /dev/null 2>&1; then
            echo "Warning: Interface $INTERFACE not found!"
            echo "Available interfaces:"
            ip link show | grep -E '^[0-9]+:' | cut -d: -f2 | tr -d ' '
            read -p "Continue anyway? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
        fi
        
        docker compose up -d
        ;;
    stop)
        echo "Stopping Zeek..."
        docker compose down
        ;;
    restart)
        echo "Restarting Zeek..."
        docker compose restart
        ;;
    logs)
        docker compose logs -f
        ;;
    status)
        docker compose ps
        echo
        echo "Recent log files:"
        ls -la logs/ | head -10
        ;;
    shell)
        docker compose exec zeek /bin/bash
        ;;
    *)
        echo "Usage: $0 {start [interface]|stop|restart|logs|status|shell}"
        echo "Example: $0 start eth0"
        exit 1
        ;;
esac
