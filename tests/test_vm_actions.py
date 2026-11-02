from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from custos.backend_setup import SetupError
from custos.vm_actions import execute, observe


class ProviderActionTests(unittest.TestCase):
    def setUp(self):
        self.remote = SimpleNamespace(provider="vcenter", endpoint="https://vc.test", service_username="shared")
        self.config = SimpleNamespace(encrypted_password="encrypted", trusted_pem=None, vcenter_uid="vc-uuid")
        self.record = SimpleNamespace(provider_ref="vm-1", provider_uid="vm-uuid")
        self.vm = Mock()
        self.vm.config.instanceUuid, self.vm.config.template = "vm-uuid", False
        self.vm.runtime.powerState = "poweredOff"
        self.vm.guest.toolsRunningStatus = "guestToolsRunning"
        self.vm.snapshot = None
        patches = [patch("custos.vm_actions.origin", return_value=SimpleNamespace(hostname="vc.test", port=443)),
                   patch("custos.vm_actions.decrypt", return_value="secret"), patch("custos.vm_actions.Disconnect"),
                   patch("custos.vm_actions.SmartConnect"), patch("custos.vm_actions.vim.VirtualMachine", return_value=self.vm)]
        self.mocks = [p.start() for p in patches]
        for p in patches:
            self.addCleanup(p.stop)
        self.service = self.mocks[3].return_value
        content = self.service.RetrieveContent.return_value
        content.about.instanceUuid = "vc-uuid"
        content.authorizationManager.HasPrivilegeOnEntity.return_value = [True]

    def test_start_uses_task_completion(self):
        task = self.vm.PowerOnVM_Task.return_value
        task._moId, task.info.state = "task-1", "success"
        callback = Mock()
        self.assertEqual(execute(self.remote, self.config, self.record, "start", "op", callback), "succeeded")
        callback.assert_called_once_with("task-1")

    def test_shutdown_never_escalates_to_poweroff(self):
        self.vm.runtime.powerState = "poweredOn"
        self.vm.ShutdownGuest.side_effect = lambda: setattr(self.vm.runtime, "powerState", "poweredOff")
        self.assertEqual(execute(self.remote, self.config, self.record, "stop", "op", Mock()), "succeeded")
        self.vm.ShutdownGuest.assert_called_once()
        self.vm.PowerOffVM_Task.assert_not_called()

    def test_reboot_remains_accepted_without_claiming_completion(self):
        self.vm.runtime.powerState = "poweredOn"
        self.assertEqual(execute(self.remote, self.config, self.record, "reboot", "op", Mock()), "accepted")
        self.vm.RebootGuest.assert_called_once()
        self.vm.ResetVM_Task.assert_not_called()

    def test_vm_uid_mismatch_blocks_execution(self):
        self.vm.config.instanceUuid = "different-vm"
        with self.assertRaises(SetupError):
            execute(self.remote, self.config, self.record, "start", "op", Mock())
        self.vm.PowerOnVM_Task.assert_not_called()

    def test_network_error_after_submission_keeps_unknown(self):
        self.vm.PowerOnVM_Task.side_effect = OSError("private provider error")
        self.assertEqual(execute(self.remote, self.config, self.record, "start", "op", Mock()), "unknown")
