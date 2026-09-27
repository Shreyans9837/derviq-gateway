class SettlementNotConfigured(RuntimeError): pass

class PaymentSettlementAdapter:
    """Provider-neutral interface. Intentionally does not move money by default."""
    def authorize(self, *args, **kwargs):
        raise SettlementNotConfigured(
            "Live financial settlement is disabled. Configure an authorized payment provider/account, "
            "legal controls, credentials and an explicit production adapter."
        )
    def capture(self, *args, **kwargs):
        raise SettlementNotConfigured("Live capture is disabled in the base Derviq distribution.")
    def reverse(self, *args, **kwargs):
        raise SettlementNotConfigured("Live reversal is provider/account dependent and disabled in the base distribution.")
