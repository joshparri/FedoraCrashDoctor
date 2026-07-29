Name:           fedora-crash-doctor
Version:        3.0.0
Release:        1%{?dist}
Summary:        Evidence-weighted crash diagnostics for Fedora
License:        MIT
URL:            https://localhost.invalid/fedora-crash-doctor
Source0:        %{name}-%{version}.tar.gz
BuildArch:      noarch

Requires:       python3
Requires:       python3-pyside6
Requires:       polkit
Requires:       systemd
Recommends:     inxi
Recommends:     smartmontools
Recommends:     nvme-cli
Recommends:     lm_sensors
Recommends:     pciutils
Recommends:     usbutils
Recommends:     fwupd
Recommends:     rasdaemon
Recommends:     edac-utils
Recommends:     fwts
Recommends:     kexec-tools
Recommends:     btrfs-progs
Recommends:     stress-ng
Recommends:     memtest86+
Recommends:     iw
Recommends:     ksystemlog
Recommends:     gnome-disk-utility

%description
Fedora Crash Doctor provides a Qt GUI, incident timeline, ranked crash
hypotheses, hardware and software evidence collection, low-write system and
KWin heartbeats, controlled tests, and a locked-down PolicyKit helper.

%prep
%autosetup

%build
# Pure Python; nothing to compile.

%install
install -d %{buildroot}%{_datadir}/fedora-crash-doctor
install -m 0755 fedora_crash_doctor.py collector.py canary.py desktop_heartbeat.py autoscan.py %{buildroot}%{_datadir}/fedora-crash-doctor/
install -m 0644 README.md LICENSE CHANGELOG.md %{buildroot}%{_datadir}/fedora-crash-doctor/

install -d %{buildroot}%{_libexecdir}/fedora-crash-doctor
install -m 0755 privileged_helper.py %{buildroot}%{_libexecdir}/fedora-crash-doctor/fedora-crash-doctor-helper

install -d %{buildroot}%{_unitdir} %{buildroot}%{_userunitdir}
install -m 0644 systemd/fedora-crash-doctor-canary.service %{buildroot}%{_unitdir}/
install -m 0644 systemd/fedora-crash-doctor-autoscan.service %{buildroot}%{_unitdir}/
install -m 0644 systemd/fedora-crash-doctor-desktop-heartbeat.service %{buildroot}%{_userunitdir}/

install -d %{buildroot}%{_datadir}/polkit-1/actions
install -m 0644 polkit/org.fedoracrashdoctor.policy %{buildroot}%{_datadir}/polkit-1/actions/

install -d %{buildroot}%{_bindir}
cat >%{buildroot}%{_bindir}/fedora-crash-doctor <<'EOF'
#!/usr/bin/env bash
exec /usr/bin/python3 /usr/share/fedora-crash-doctor/fedora_crash_doctor.py "$@"
EOF
chmod 0755 %{buildroot}%{_bindir}/fedora-crash-doctor

install -d %{buildroot}%{_datadir}/applications
cat >%{buildroot}%{_datadir}/applications/fedora-crash-doctor.desktop <<'EOF'
[Desktop Entry]
Type=Application
Name=Fedora Crash Doctor
GenericName=Crash Diagnostics
Comment=Evidence-weighted hardware and software crash diagnostics
Exec=fedora-crash-doctor
Icon=utilities-system-monitor
Terminal=false
Categories=System;
Keywords=crash;diagnostics;hardware;logs;fedora;kdump;smart;
StartupNotify=true
EOF

%post
%systemd_post fedora-crash-doctor-canary.service fedora-crash-doctor-autoscan.service
systemctl --global enable fedora-crash-doctor-desktop-heartbeat.service >/dev/null 2>&1 || :

%preun
%systemd_preun fedora-crash-doctor-canary.service fedora-crash-doctor-autoscan.service

%postun
%systemd_postun_with_restart fedora-crash-doctor-canary.service fedora-crash-doctor-autoscan.service

%files
%license LICENSE
%doc README.md CHANGELOG.md
%{_bindir}/fedora-crash-doctor
%{_datadir}/fedora-crash-doctor/
%{_libexecdir}/fedora-crash-doctor/
%{_unitdir}/fedora-crash-doctor-canary.service
%{_unitdir}/fedora-crash-doctor-autoscan.service
%{_userunitdir}/fedora-crash-doctor-desktop-heartbeat.service
%{_datadir}/polkit-1/actions/org.fedoracrashdoctor.policy
%{_datadir}/applications/fedora-crash-doctor.desktop

%changelog
* Wed Jul 29 2026 Fedora Crash Doctor contributors <noreply@example.invalid> - 3.0.0-1
- Initial packaged v3 release
