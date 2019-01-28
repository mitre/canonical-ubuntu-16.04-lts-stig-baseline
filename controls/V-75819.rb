control "V-75819" do
  title "The Ubuntu operating system must implement non-executable data to
protect its memory from unauthorized code execution."
  desc  "Some adversaries launch attacks with the intent of executing code in
non-executable regions of memory or in memory locations that are prohibited.
Security safeguards employed to protect memory include, for example, data
execution prevention and address space layout randomization. Data execution
prevention safeguards can either be hardware-enforced or software-enforced with
hardware providing the greater strength of mechanism.

    Examples of attacks are buffer overflow attacks.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000433-GPOS-00192"
  tag "gid": "V-75819"
  tag "rid": "SV-90499r2_rule"
  tag "stig_id": "UBTU-16-030130"
  tag "fix_id": "F-82449r1_fix"
  tag "cci": ["CCI-002824"]
  tag "nist": ["SI-16", "Rev_4"]
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
  desc "check", "Verify the NX (no-execution) bit flag is set on the system.

Check that the no-execution bit flag is set with the following commands:

# dmesg | grep NX

[    0.000000] NX (Execute Disable) protection: active

If \"dmesg\" does not show \"NX (Execute Disable) protection\" active, check
the cpuinfo settings with the following command:

# less /proc/cpuinfo | grep -i flags
flags       : fpu vme de pse tsc ms nx rdtscp lm constant_tsc

If \"flags\" does not contain the \"nx\" flag, this is a finding."
  tag "fix": "The NX bit execute protection must be enabled in the system BIOS."
end

