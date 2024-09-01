package scanner

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/schniggie/orfinder/internal/config"
	"github.com/schniggie/orfinder/internal/openrelay"
	"golang.org/x/net/proxy"
	"golang.org/x/sys/unix"
)

var useRawSockets bool

func init() {
	useRawSockets = checkRawSocketCapability()
}

// UseRawSockets returns whether the scanner is using raw sockets
func UseRawSockets() bool {
	return useRawSockets
}

func checkRawSocketCapability() bool {
	if unix.Geteuid() == 0 {
		return true // Root user can always use raw sockets
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err == nil {
		unix.Close(fd)
		return true
	}
	return false
}

// Scan performs a scan on the given IP range
func Scan(ctx context.Context, ipRange string, cfg *config.Config, vulnerableServers chan<- string) error {
	ip, ipnet, err := net.ParseCIDR(ipRange)
	if err != nil {
		return fmt.Errorf("failed to parse CIDR: %w", err)
	}

	if cfg.Debug {
		log.Printf("Starting scan of IP range: %s", ipRange)
		log.Printf("Using raw sockets: %v", useRawSockets)
	}

	count := 0
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		count++
		if cfg.Debug && count%10 == 0 {
			log.Printf("Processed %d IPs in range %s", count, ipRange)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if err := scanIP(ctx, ip, cfg, vulnerableServers); err != nil {
				log.Printf("Error scanning %s: %v", ip, err)
				continue // Continue with next IP instead of returning
			}
		}
	}

	if cfg.Debug {
		log.Printf("Completed scan of IP range: %s. Total IPs processed: %d", ipRange, count)
	}

	return nil
}

func scanIP(ctx context.Context, ip net.IP, cfg *config.Config, vulnerableServers chan<- string) error {
	if cfg.Debug {
		log.Printf("Scanning IP: %s", ip)
	}

	for _, port := range cfg.Ports {
		var isOpen bool
		var err error

		if useRawSockets && !cfg.UseTor {
			isOpen, err = portIsOpenRaw(ctx, ip, port, cfg.Timeout)
		} else {
			isOpen, err = portIsOpenTCP(ctx, ip.String(), port, cfg.Timeout, cfg.UseTor)
		}

		if err != nil {
			log.Printf("Error checking port %d on %s: %v", port, ip, err)
			continue
		}

		if cfg.Debug {
			log.Printf("Port %d open on %s: %v", port, ip, isOpen)
		}

		if isOpen {
			isVulnerable, err := openrelay.IsVulnerable(ctx, ip, port, cfg)
			if err != nil {
				log.Printf("Error checking open relay for %s:%d: %v", ip, port, err)
				continue
			}

			if isVulnerable {
				result := fmt.Sprintf("[+] %s:%d is vulnerable to open relay attack", ip, port)
				vulnerableServers <- result
				if cfg.Debug {
					log.Println(result)
				}
			} else if cfg.Debug {
				log.Printf("[-] %s:%d is not vulnerable to open relay attack", ip, port)
			}
		}
	}

	return nil
}

func portIsOpenRaw(ctx context.Context, dstIP net.IP, dstPort int, timeout time.Duration) (bool, error) {
	srcIP, srcPort, err := getLocalAddress(dstIP)
	if err != nil {
		return false, fmt.Errorf("failed to get local address: %w", err)
	}

	ip := &layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
	}

	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if err := gopacket.SerializeLayers(buf, opts, tcp); err != nil {
		return false, fmt.Errorf("failed to serialize layers: %w", err)
	}

	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return false, fmt.Errorf("failed to listen: %w", err)
	}
	defer conn.Close()

	if _, err := conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: dstIP}); err != nil {
		return false, fmt.Errorf("failed to send packet: %w", err)
	}

	deadline := time.Now().Add(timeout)
	err = conn.SetReadDeadline(deadline)
	if err != nil {
		return false, fmt.Errorf("failed to set read deadline: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		default:
			b := make([]byte, 4096)
			n, addr, err := conn.ReadFrom(b)
			if err != nil {
				if err, ok := err.(net.Error); ok && err.Timeout() {
					return false, nil
				}
				return false, fmt.Errorf("failed to read: %w", err)
			}

			if addr.String() == dstIP.String() {
				packet := gopacket.NewPacket(b[:n], layers.LayerTypeTCP, gopacket.Default)
				if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
					tcp, _ := tcpLayer.(*layers.TCP)
					if tcp.SYN && tcp.ACK {
						return true, nil
					}
				}
			}
		}
	}
}

func portIsOpenTCP(ctx context.Context, host string, port int, timeout time.Duration, useTor bool) (bool, error) {
	addr := fmt.Sprintf("%s:%d", host, port)

	var conn net.Conn
	var err error

	if useTor {
		dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:9050", nil, proxy.Direct)
		if err != nil {
			log.Printf("Failed to create SOCKS5 dialer: %v. Falling back to direct connection.", err)
			useTor = false
		} else {
			contextDialer, ok := dialer.(proxy.ContextDialer)
			if !ok {
				return false, fmt.Errorf("failed to create context dialer")
			}
			conn, err = contextDialer.DialContext(ctx, "tcp", addr)
		}
	}

	if !useTor {
		var d net.Dialer
		d.Timeout = timeout
		conn, err = d.DialContext(ctx, "tcp", addr)
	}

	if err != nil {
		return false, nil // Consider port closed if connection fails
	}
	if conn != nil {
		defer conn.Close()
	}

	return true, nil
}

func getLocalAddress(dstIP net.IP) (net.IP, int, error) {
	conn, err := net.Dial("udp", dstIP.String()+":12345")
	if err != nil {
		return nil, 0, fmt.Errorf("failed to dial: %w", err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP, localAddr.Port, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
