control "V-75511" do
  title "All public directories must be owned by root to prevent unauthorized
and unintended information transferred via shared system resources."
  desc  "Preventing unauthorized information transfers mitigates the risk of
information, including encrypted representations of information, produced by
the actions of prior users/roles (or the actions of processes acting on behalf
of prior users/roles) from being available to any current users/roles (or
current processes) that obtain access to shared system resources (e.g.,
registers, main memory, hard disks) after those resources have been released
back to information systems. The control of information in shared resources is
also commonly referred to as object reuse and residual information protection.

    This requirement generally applies to the design of an information
technology product, but it can also apply to the configuration of particular
information system components that are, or use, such products. This can be
verified by acceptance/validation processes in DoD or other government agencies.

    There may be shared resources with configurable protections (e.g., files in
storage) that may be assessed on specific information system components.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000138-GPOS-00069"
  tag "gid": "V-75511"
  tag "rid": "SV-90191r1_rule"
  tag "stig_id": "UBTU-16-010410"
  tag "fix_id": "F-82139r1_fix"
  tag "cci": ["CCI-001090"]
  tag "nist": ["SC-4", "Rev_4"]
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
  desc "check", "Verify that all public directories are owned by root to prevent
unauthorized and unintended information transferred via shared system resources.

Check to see that all public directories have the public sticky bit set by
running the following command:

# sudo find / -type d -perm -0002 -exec ls -lLd {} \\;

drwxrwxrwxt 7 root root 4096 Jul 26 11:19 /tmp

If any of the returned directories are not owned by root, this is a finding."
  desc "fix", "Configure all public directories to be owned by root to prevent
unauthorized and unintended information transferred via shared system resources.

Set the owner of all public directories as root using the command, replace
\"[Public Directory]\" with any directory path not owned by root:

# sudo chown root [Public Directory]"

  command("sudo find / -type d -perm -0002 -exec ls -dL {} \\;").stdout.strip.split("\n").each do |entry|
    describe directory(entry) do
      its('owner') { should eq 'root' }
    end
  end
end

