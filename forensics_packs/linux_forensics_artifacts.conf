SELECT 
address, hostnames 
FROM etc_hosts 
WHERE 
hostnames NOT IN ("localhost", "::1", "fe00::0", "ff00::0", "ff02::1", "ff02::2");
SELECT 
p.pid, p.name, p.path, p.cmdline, p.state,  h.sha256 
FROM processes p 
INNER JOIN hash h 
ON p.path=h.path;
SELECT 
interface, address, mask, type, friendly_name 
FROM interface_addresses 
WHERE 
interface NOT LIKE "lo%" AND 
interface!=1;
SELECT 
pid, name, path, cmdline, state 
FROM processes 
WHERE 
on_disk=0;
SELECT 
user, type as "login_type", tty as "device_name", host as "remote_hostname", DATETIME(time, "unixepoch", "UTC") AS time, pid, sid  
FROM logged_in_users
WHERE 
user!="";
SELECT 
de.name, de.uuid, de.encrypted, de.type, u.username, de.user_uuid, de.encryption_status 
FROM disk_encryption de
LEFT JOIN users u 
ON de.uid=u.uid;
SELECT 
name, version, major, minor, patch, build, platform, codename, install_date
FROM os_version;
SELECT 
p.name, p.path, lp.address, lp.protocol, lp.port 
FROM listening_ports lp LEFT JOIN processes p ON lp.pid = p.pid 
WHERE 
lp.port != 0 
AND lp.address!="127.0.0.1" 
AND lp.address!="::1" 
AND p.path NOT LIKE "/usr/sbin/%" 
AND p.path NOT LIKE "/sbin/%" 
AND p.path NOT LIKE "/usr/libexec/%";
SELECT 
uid, gid, username, description, directory, shell, uuid, type 
FROM users;
SELECT 
usb_address, usb_port, vendor, version, model, serial, class, subclass, protocol, removable 
FROM usb_devices;
SELECT 
DISTINCT pos.pid, p.name, p.cmdline, pos.local_address, pos.local_port, pos.remote_address, pos.remote_port 
FROM processes p 
JOIN process_open_sockets pos USING (pid)
WHERE 
pos.remote_address NOT IN ("", "0.0.0.0", "127.0.0.1", "::", "::1", "0");
SELECT 
g.groupname, u.username, g.comment
FROM groups g
LEFT JOIN user_groups ug ON g.gid=ug.gid
LEFT JOIN users u ON ug.uid=u.uid;
SELECT 
device, device_alias, path, type, blocks_size, blocks, blocks_free, blocks_available, inodes, inodes_free, flags
FROM mounts;
CREATE TEMPORARY TABLE loaded_modules AS 
SELECT 
DISTINCT(path) 
FROM process_memory_map;
CREATE TEMPORARY TABLE loaded_module_hashes AS 
SELECT 
d.rowid AS module_id, h.sha256 AS sha256, d.path AS module_path 
FROM hash h 
INNER JOIN loaded_modules d ON d.path=h.path;
SELECT 
module_id, sha256, module_path 
FROM loaded_module_hashes;
SELECT 
pid, name AS process_name, path AS process_path 
FROM processes;
SELECT 
DISTINCT lh.module_id, pmm.pid AS pid 
FROM process_memory_map pmm 
JOIN loaded_module_hashes lh ON lh.module_path=pmm.path;
SELECT
address, mac, interface, permanent
FROM
arp_cache;
SELECT 
u.username, ce.name, ce.identifier, ce.version, ce.description, ce.locale, ce.update_url, ce.persistent, ce.path
FROM users u
CROSS JOIN chrome_extensions ce USING (uid);
SELECT
event, minute, hour, day_of_month, month, day_of_week,
command, path
FROM
crontab;
SELECT
id, type, address as ip, netmask, options
FROM dns_resolvers;
SELECT
name, port, protocol, aliases, comment
FROM
etc_services;
SELECT
name, number, alias, comment
FROM
etc_protocols;
SELECT 
filter_name, chain, policy, target, protocol, 
src_ip AS "source ip", src_mask AS "source mask", src_port AS "source port", 
dst_ip AS "destination ip", dst_mask AS "destination mask", dst_port AS "destination port",
iniface AS "input interface",
outiface AS "output interface",
match AS "matching rule",
packets, bytes
FROM iptables;
SELECT 
name, size, used_by, status, address 
FROM kernel_modules;
SELECT
u.username, kn.uid, kn.key, kn.key_file
FROM users u
JOIN known_hosts kn USING(uid);
SELECT
l.username, l.tty, l.pid,
p.name AS "process name",
l.type,
DATETIME(l.time, "unixepoch", "UTC") AS "entry timestamp",
l.host as hostname
FROM last l
LEFT JOIN processes p ON p.pid = l.pid;
SELECT 
vendor, version, date, revision, address, size, volume_size, extra
FROM platform_info;
SELECT
p.name AS "Process Name", p.pid,
pe.key AS "Environment Variable Name",
pe.value AS "Environment Variable Value"
FROM process_envs pe
JOIN processes p ON p.pid=pe.pid;
SELECT
password_status, hash_alg, last_change,
min, max, warning, inactive,
expire, username 
FROM shadow;
SELECT 
u.username, sh.time, sh.command, sh.history_file
FROM users u
CROSS JOIN shell_history sh USING (uid);
SELECT 
u.username, sc.block, sc.option, sc.ssh_config_file, h.sha256
FROM users u
JOIN ssh_configs sc USING(uid)
JOIN hash h ON h.path = sc.ssh_config_file;
SELECT 
name, path, args, source, type, status, username
FROM startup_items;
SELECT
source, header, rule_details
FROM sudoers;
SELECT 
f.path, sb.username, sb.groupname, f.mode, sb.permissions
FROM suid_bin sb
LEFT JOIN file f ON sb.path = f.path
WHERE
sb.permissions LIKE regex_match(sb.permissions, "(S|G)", 0) AND
f.mode LIKE regex_match(f.mode, ".*(2|3|6|7)$", 0);
SELECT 
hostname, local_hostname, cpu_type, cpu_subtype, cpu_brand, physical_memory
FROM system_info;
SELECT 
u.username, usk.path, usk.encrypted, sha256
FROM users u
JOIN user_ssh_keys usk
USING (uid)
JOIN hash h ON h.path=usk.path;
SELECT
id, description, load_state, active_state, sub_state, following,
object_path, job_id, job_type, job_path,
fragment_path, user, source_path
FROM
systemd_units;