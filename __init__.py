# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
from trytond.pool import Pool
from .monitoring import *

__all__ = ['CheckType', 'ResultType', 'StateType', 'StateIndicator',
    'StateIndicatorLine', 'Scheduler', 'CheckPlan', 'IndicatorCheckPlan',
    'Check', 'State', 'ResultInteger', 'ResultFloat', 'ResultChar',
    'AssetPartyNotification', 'Asset', 'Party']

def register():
    Pool.register(
        CheckType,
        ResultType,
        StateType,
        StateIndicator,
        StateIndicatorLine,
        Scheduler,
        CheckPlan,
        StateIndicatorCheckPlan,
        Check,
        State,
        ResultInteger,
        ResultFloat,
        ResultChar,
        AssetPartyNotification,
        Asset,
        StateTypeParty,
        Party,
        module='monitoring', type_='model')
