control "V-75581" do
  title "File systems that are being imported via Network File System (NFS)
must be mounted to prevent binary files from being executed."
  desc  "The \"noexec\" mount option causes the system to not execute binary
files. This option must be used for mounting any file system not containing
approved binary files as they may be incompatible. Executing files from
untrusted file systems increases the opportunity for unprivileged users to
attain unauthorized administrative access."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75581"
  tag "rid": "SV-90261r2_rule"
  tag "stig_id": "UBTU-16-010830"
  tag "fix_id": "F-82209r2_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
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
  desc "check", "Verify file systems that are being Network File System (NFS)
imported are mounted with the \"noexec\" option.

Find the file system(s) that contain the directories being exported with the
following command:

# grep nfs /etc/fstab | grep noexec

UUID=e06097bb-cfcd-437b-9e4d-a691f5662a7d    /store           nfs
rw,noexec                                                    0 0

If a file system found in \"/etc/fstab\" refers to NFS and it does not have the
\"noexec\" option set, and use of NFS exported binaries is not documented with
the Information System Security Officer (ISSO) as an operational requirement,
this is a finding."
  desc "fix", "Configure the \"/etc/fstab\" to use the \"noexec\" option on file
systems that are being imported via Network File System (NFS)."
end

