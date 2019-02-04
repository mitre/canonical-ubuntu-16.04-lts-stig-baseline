control "V-75531" do
  title "Automatic mounting of Universal Serial Bus (USB) mass storage driver
must be disabled."
  desc  "Without authenticating devices, unidentified or unknown devices may be
introduced, thereby facilitating malicious activity.

    Peripherals include, but are not limited to, such devices as flash drives,
external storage, and printers.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000378-GPOS-00163"
  tag "gid": "V-75531"
  tag "rid": "SV-90211r2_rule"
  tag "stig_id": "UBTU-16-010580"
  tag "fix_id": "F-82159r2_fix"
  tag "cci": ["CCI-001958"]
  tag "nist": ["IA-3", "Rev_4"]
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
  desc "check", "Verify that automatic mounting of the Universal Serial Bus
(USB) mass storage driver has been disabled.

Check that the USB mass storage drive has not been loaded with the following
command:

#lsmod | grep usb-storage

If a \"usb-storage\" line is returned, this is a finding.

Check that automatic mounting of the USB mass storage driver has been disabled
with the following command:

#sudo modprobe -vn  usb-storage

install /bin/true

If “install /bin/true” is not returned, this is a finding."
  desc "fix", "Disable the mounting of the Universal Serial Bus (USB) mass
storage driver by running the following command:

# sudo echo “install usb-storage /bin/true” >> /etc/modprobe.d/DISASTIG.conf"
end

