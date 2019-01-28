control "V-75533" do
  title "File system automounter must be disabled unless required."
  desc  "Automatically mounting file systems permits easy introduction of
unknown devices, thereby facilitating malicious activity.


  "
  impact 0.5
  tag "gtitle": "SRG-OS-000114-GPOS-00059"
  tag "satisfies": ["SRG-OS-000114-GPOS-00059", "SRG-OS-000378-GPOS-00163",
"SRG-OS-000480-GPOS-00227"]
  tag "gid": "V-75533"
  tag "rid": "SV-90213r2_rule"
  tag "stig_id": "UBTU-16-010590"
  tag "fix_id": "F-82161r2_fix"
  tag "cci": ["CCI-000366", "CCI-000778", "CCI-001958"]
  tag "nist": ["CM-6 b", "IA-3", "IA-3", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  desc "check", "Verify the Ubuntu operating system disables the ability to
automount devices.

Check to see if automounter service is active with the following command:

# systemctl status autofs
 autofs.service - LSB: Automounts filesystems on demand
   Loaded: loaded (/etc/init.d/autofs; bad; vendor preset: enabled)
   Active: active (running) since Thu 2017-05-04 07:53:51 EDT; 6 days ago
     Docs: man:systemd-sysv-generator(8)
   CGroup: /system.slice/autofs.service
           +-24206 /usr/sbin/automount --pid-file /var/run/autofs.pid

If the \"autofs\" status is set to \"active\" and is not documented with the
Information System Security Officer (ISSO) as an operational requirement, this
is a finding."
  tag "fix": "Configure the Ubuntu operating system to disable the ability to
automount devices.

Turn off the automount service with the following command:

# sudo systemctl stop autofs

If \"autofs\" is required for Network File System (NFS), it must be documented
with the Information System Security Officer (ISSO)."
end

