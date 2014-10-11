# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
from trytond.pool import Pool
from .monitoring import *

def register():
    Pool.register(
        CheckType,
        ResultType,
        Scheduler,
        CheckPlan,
        Check,
        ResultInteger,
        ResultFloat,
        ResultChar,
        Alert,
        AlertAsset,
        Asset,
        module='network_monitoring', type_='model')
