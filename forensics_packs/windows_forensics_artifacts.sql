SELECT address, hostnames 
FROM etc_hosts 
WHERE hostnames NOT IN ("localhost", "::1", "fe00::0", "ff00::0", "ff02::1", "ff02::2");
SELECT p.pid, p.name, p.path, h.sha256 
FROM processes p INNER JOIN hash h ON p.path=h.path;
SELECT ld.device_id, ld.type, ld.free_space, ld.size, ld.file_system, ld.boot_partition, bi.encryption_method 
FROM logical_drives ld
LEFT JOIN bitlocker_info bi ON ld.device_id=bi.drive_letter;
SELECT interface, address 
FROM interface_addresses 
WHERE interface NOT LIKE "lo%" 
AND interface!=1;
SELECT name, path, pid 
FROM processes 
WHERE on_disk=0;
SELECT description, install_date, status, allow_maximum, maximum_allowed, name, path, type
FROM shared_resources;
SELECT apps.executable, h.sha256, apps.path, apps.description, datetime(apps.install_time,"unixepoch", "UTC") AS install_time, apps.sdb_id 
FROM appcompat_shims apps LEFT JOIN hash h ON h.path=apps.path;
SELECT user, logon_domain, authentication_package, logon_type, DATETIME(logon_time,"unixepoch","UTC") AS logon_time, logon_server, dns_domain_name, upn, logon_script,
profile_path, home_directory, home_directory_drive
FROM logon_sessions;
SELECT DISTINCT user 
FROM logged_in_users
WHERE user!="";
SELECT f.path, f.filename, f.uid, f.gid, f.mode, f.size,
DATETIME(f.atime, "unixepoch","UTC") AS last_access_time,
DATETIME(f.mtime, "unixepoch", "UTC") AS last_modified,
DATETIME(f.ctime, "unixepoch", "UTC") AS last_status_change_time,
DATETIME(f.btime, "unixepoch", "UTC") AS creation_time,
f.hard_links, f.symlink, f.type
FROM file f
WHERE f.path LIKE "C:\Users\%\AppData\Roaming\Microsoft\Windows\Recent\%";
SELECT script_text, datetime
FROM orbital_powershell_events
ORDER BY datetime DESC
LIMIT 500;
SELECT platform, name, major, minor, build 
FROM os_version;
SELECT DISTINCT ae.name, ae.path, ae.source, h.sha256 
FROM autoexec ae LEFT JOIN hash h ON h.path = ae.path;
SELECT hotfix_id, caption, description, fix_comments, installed_by, install_date, installed_on
FROM patches
ORDER BY installed_on;
SELECT p.name, p.path, lp.address, lp.protocol, lp.port 
FROM listening_ports lp LEFT JOIN processes p ON lp.pid = p.pid 
WHERE lp.port != 0 
AND lp.address!="127.0.0.1" 
AND lp.address!="::1" 
AND p.path NOT LIKE "c:\windows\system32\%" 
AND p.path NOT LIKE "/usr/sbin/%" 
AND p.path NOT LIKE "/sbin/%" 
AND p.path NOT LIKE "/usr/libexec/%";
SELECT name, path, args, source, type, status, username 
FROM startup_items;
SELECT name, version, publisher, install_date 
FROM programs 
WHERE name!="" OR publisher!="";
SELECT uid, gid, username, description, directory, shell, uuid, type 
FROM users;
SELECT filename, uid, gid, 
datetime(atime, "unixepoch", "UTC") as last_access_time,
datetime(mtime, "unixepoch", "UTC") as last_modification_time,
datetime(ctime, "unixepoch", "UTC") as last_status_change_time, 
datetime(btime, "unixepoch", "UTC") as create_time,
hard_links, symlink, type, attributes, volume_serial, file_id 
FROM file 
WHERE path LIKE "C:\Windows\Prefetch\%" 
AND size NOT LIKE "0";
SELECT key AS reg_key, path, name, data, datetime(mtime, "unixepoch", "UTC") AS last_modified
FROM registry
WHERE key LIKE "HKEY_USERS\%\Network\%";
SELECT key AS reg_key, path, name, data, DATETIME(mtime, "unixepoch", "UTC") AS last_modified
FROM registry
WHERE key LIKE "HKEY_LOCAL_MACHINE\Software\microsoft\windows nt\currentversion\networklist\profiles\%"
AND name IN ("ProfileName", "DateCreated", "DateLastConnected", "Description");
SELECT DISTINCT pos.pid, p.name, p.cmdline, pos.local_address, pos.local_port, pos.remote_address, pos.remote_port 
FROM processes p JOIN process_open_sockets pos USING (pid)
WHERE pos.remote_address NOT IN ("", "0.0.0.0", "127.0.0.1", "::", "::1", "0");
SELECT g.groupname, u.username, g.comment
FROM groups g
LEFT JOIN user_groups ug ON g.gid=ug.gid
LEFT JOIN users u ON ug.uid=u.uid;
SELECT description, install_date, status, allow_maximum, maximum_allowed, name, path, type
FROM shared_resources
ORDER BY install_date;
CREATE TEMPORARY TABLE loaded_modules AS 
SELECT DISTINCT(path) 
FROM process_memory_map;
CREATE TEMPORARY TABLE loaded_module_hashes AS 
SELECT d.rowid AS module_id, h.sha256 AS sha256, d.path AS module_path 
FROM hash h INNER JOIN loaded_modules d ON d.path=h.path;
SELECT module_id, sha256, module_path 
FROM loaded_module_hashes;
SELECT pid, name AS process_name, path AS process_path 
FROM processes;
SELECT DISTINCT lh.module_id, pmm.pid AS pid 
FROM process_memory_map pmm JOIN loaded_module_hashes lh ON lh.module_path=pmm.path;
SELECT key AS reg_key, path, name, data, DATETIME(mtime, "unixepoch", "UTC") AS last_modified
FROM registry
WHERE key LIKE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR\%";
SELECT name, action, path, enabled, state, hidden, last_run_time, next_run_time, last_run_message, last_run_code
FROM scheduled_tasks;
SELECT f.path, f.filename, h.sha256, f.uid, f.gid, f.mode, f.size, 
DATETIME(f.atime, "unixepoch","UTC") AS last_access_time, 
DATETIME(f.mtime, "unixepoch", "UTC") AS last_modified, 
DATETIME(f.ctime, "unixepoch", "UTC") AS last_status_change_time, 
DATETIME(f.btime, "unixepoch", "UTC") AS creation_time,
f.hard_links, f.symlink, f.type
FROM file f LEFT JOIN hash h ON f.path=h.path
WHERE f.path LIKE "C:\Users\%\AppData\Local\Temp\%%";