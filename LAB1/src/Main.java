import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;


public class Main {

    // ===== ARP ENTRY =====
    static class ArpEntry {
        String ip;
        String mac;
        String type;

        ArpEntry(String ip, String mac, String type) {
            this.ip = ip;
            this.mac = mac;
            this.type = type;
        }
    }

    private static final List<ArpEntry> arpTable = new ArrayList<>();

    // ===== MAIN =====
    public static void main(String[] args) throws Exception {
        System.out.println("=== СОБСТВЕННЫЙ КОМПЬЮТЕР ===");
        printLocalMachineInfo();

        System.out.println("\n=== СКАНИРОВАНИЕ СЕТИ ===");
        scanNetwork();

        System.out.println("\n=== ARP-ТАБЛИЦА ===");
        loadArpTable();
        printArpTable();
    }

    // ===== 1. LOCAL MACHINE =====
    private static void printLocalMachineInfo() throws Exception {
        Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();

        while (interfaces.hasMoreElements()) {
            NetworkInterface ni = interfaces.nextElement();

            if (!ni.isUp() || ni.isLoopback()) continue;

            byte[] mac = ni.getHardwareAddress();
            if (mac == null) continue;

            System.out.println("Интерфейс: " + ni.getDisplayName());
            System.out.println("  MAC: " + macToString(mac));

            for (InterfaceAddress ia : ni.getInterfaceAddresses()) {
                if (ia.getAddress() instanceof Inet4Address) {
                    System.out.println("  IP: " +
                            ia.getAddress().getHostAddress() +
                            "/" + ia.getNetworkPrefixLength());
                }
            }
        }
    }

    // ===== 2. NETWORK SCAN =====
    private static void scanNetwork() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(64);

        Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();

        while (interfaces.hasMoreElements()) {
            NetworkInterface ni = interfaces.nextElement();

            if (!ni.isUp() || ni.isLoopback()) continue;

            for (InterfaceAddress ia : ni.getInterfaceAddresses()) {
                if (!(ia.getAddress() instanceof Inet4Address)) continue;

                List<String> hosts = getIpRange(ia);

                System.out.println("Подсеть: " +
                        ia.getAddress().getHostAddress() +
                        "/" + ia.getNetworkPrefixLength() +
                        " | Хостов: " + hosts.size());

                for (String host : hosts) {
                    pool.submit(() -> ping(host));
                }
            }
        }

        pool.shutdown();
        pool.awaitTermination(40, TimeUnit.SECONDS);
    }

    private static void ping(String ip) {
        try {
            InetAddress addr = InetAddress.getByName(ip);
            if (addr.isReachable(700)) {
                System.out.println("Доступен: " + ip +
                        " | Имя: " + addr.getCanonicalHostName());
            }
        } catch (IOException ignored) {}
    }

    // ===== 3. LOAD ARP =====
    private static void loadArpTable() throws IOException {
        Process process = Runtime.getRuntime().exec("arp -a");

        BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), Charset.forName("CP866"))
        );

        String line;
        while ((line = reader.readLine()) != null) {
            line = line.trim();

            // строки вида: IP  MAC  TYPE
            if (!line.matches("\\d+\\.\\d+\\.\\d+\\.\\d+\\s+.*")) continue;

            String[] parts = line.split("\\s+");
            if (parts.length < 3) continue;

            String ip = parts[0];
            String mac = parts[1];
            String type = parts[2];

            if (mac.equalsIgnoreCase("ff-ff-ff-ff-ff-ff")) continue;
            if (ip.startsWith("224.") || ip.startsWith("239.")) continue;

            arpTable.add(new ArpEntry(ip, mac, type));
        }
    }

    // ===== 4. PRINT ARP =====
    private static void printArpTable() {
        if (arpTable.isEmpty()) {
            System.out.println("ARP-таблица пуста");
            return;
        }

        for (ArpEntry e : arpTable) {
            System.out.println("IP: " + e.ip +
                    " | MAC: " + e.mac +
                    " | TYPE: " + e.type);
        }
    }

    // ===== HELPERS =====
    private static String macToString(byte[] mac) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < mac.length; i++) {
            sb.append(String.format("%02X", mac[i]));
            if (i < mac.length - 1) sb.append("-");
        }
        return sb.toString();
    }

    private static List<String> getIpRange(InterfaceAddress ia) {
        List<String> result = new ArrayList<>();

        Inet4Address inet = (Inet4Address) ia.getAddress();
        int prefix = ia.getNetworkPrefixLength();

        int ip = ByteBuffer.wrap(inet.getAddress()).getInt();
        int mask = prefix == 0 ? 0 : (-1 << (32 - prefix));

        int network = ip & mask;
        int broadcast = network | ~mask;

        for (int i = network + 1; i < broadcast; i++) {
            result.add(intToIp(i));
        }
        return result;
    }

    private static String intToIp(int ip) {
        return ((ip >> 24) & 0xFF) + "." +
                ((ip >> 16) & 0xFF) + "." +
                ((ip >> 8) & 0xFF) + "." +
                (ip & 0xFF);
    }
}
