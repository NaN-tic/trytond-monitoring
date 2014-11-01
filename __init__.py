# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
from trytond.pool import Pool
from .monitoring import *

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
        RelationType,
        module='monitoring', type_='model')
