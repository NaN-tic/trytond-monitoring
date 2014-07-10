# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
import sys
from datetime import datetime

from trytond.model import ModelSQL, ModelView, fields
from trytond.pool import Pool, PoolMeta
from trytond.pyson import Eval


__all__ = ['CheckType', 'ResultType', 'Scheduler', 'CheckPlan', 'Check',
    'ResultInteger', 'ResultFloat', 'ResultChar', 'Alert', 'AlertItem', 'Item']
__metaclass__ = PoolMeta


class CheckType(ModelSQL, ModelView):
    'Monitoring Check Type'
    __name__ = 'monitoring.check.type'
    name = fields.Char('Name', translate=True)
    internal_name = fields.Char('Internal Name', readonly=False)

    def check(self, check_plan):
        res = getattr(self, self.internal_name)(check_plan)
        return res

    def check_cpu_times_percent(self, check):
        import psutil
        usage = psutil.cpu_times_percent(interval=1)
        res = []
        for name in ('user', 'nice', 'system', 'idle', 'iowait', 'irq',
                'softirq', 'steal', 'guest', 'nice'):
            res.append({
                    'result': 'cpu_percent_%s' % name,
                    'float_value': getattr(usage, name),
                    })
        return res

    def check_cpu_percent(self, check):
        import psutil
        usage = psutil.cpu_percent(interval=1)
        return {
            'result': 'cpu_percent',
            'float_value': usage,
            }

    def check_disk(self, check):
        import psutil
        path = check.item.get_attribute('path')
        usage = psutil.disk_usage(path)
        res = []
        for name in ('total', 'used', 'free', 'percent'):
            res.append({
                    'result': 'disk_usage_%s' % name,
                    'float_value': getattr(usage, name),
                    })
        return res

    def check_disk_io_counters(self, check):
        import psutil
        usage = psutil.disk_io_counters(perdisk=False)
        res = []
        for name in ('read_count', 'write_count', 'read_bytes', 'write_bytes',
                'read_time', 'write_time'):
            res.append({
                    'result': 'disk_io_counter_%s' % name,
                    'float_value': getattr(usage, name),
                    })
        return res

    def check_swap(self, check):
        import psutil
        usage = psutil.swap_memory()
        res = []
        for name in ('total', 'used', 'free', 'percent', 'sin', 'sout'):
            res.append({
                    'result': 'swap_usage_%s' % name,
                    'float_value': getattr(usage, name),
                    })
        return res

    def check_physical_memory(self, check):
        import psutil
        usage = psutil.phymem_usage()
        res = []
        for name in ('total', 'available', 'percent', 'used', 'free', 'active',
                'inactive', 'buffers', 'cached'):
            res.append({
                    'result': 'physical_memory_usage_%s' % name,
                    'float_value': getattr(usage, name),
                    })
        return res

    def check_net_io_counters(self, check):
        import psutil
        interface = check.item.get_attribute('interface')
        pernic = bool(interface)
        usage = psutil.net_io_counters(pernic=pernic)
        if interface:
            usage = usage[interface]
        res = []
        for name in ('bytes_sent', 'bytes_recv', 'packets_sent', 'packets_recv',
                'errin', 'errout', 'dropin', 'dropout'):
            res.append({
                    'result': 'net_io_counter_%s' % name,
                    'float_value': getattr(usage, name),
                    })
        return res


class ResultType(ModelSQL, ModelView):
    'Monitoring Result Type'
    __name__ = 'monitoring.result.type'
    name = fields.Char('Name')
    internal_name = fields.Char('Internal Name', readonly=False)
    type = fields.Selection([
            ('integer', 'Integer'),
            ('float', 'Float'),
            ('char', 'Char'),
            ], 'Type', required=True)
    uom = fields.Many2One('product.uom', 'UoM', states={
            'required': Eval('type').in_(['integer', 'float']),
            'invisible': ~Eval('type').in_(['integer', 'float']),
            })


class Scheduler(ModelSQL, ModelView):
    'Monitoring Scheduler'
    __name__ = 'monitoring.scheduler'
    # It might make sense to create a parent and inherit values from the
    # parent similar to Nagios behaviour.
    name = fields.Char('Name', required=True)
    normal_check_interval = fields.Float('Normal Check Interval', required=True)
    retries = fields.Integer('Retries', required=True)
    retry_check_interval = fields.Float('Retry Check Interval', required=True)


# We should probably create a scheduler queue

class CheckPlan(ModelSQL, ModelView):
    'Monitoring Check Plan'
    __name__ = 'monitoring.check.plan'
    item = fields.Many2One('network.item', 'Item', required=True)
    type = fields.Many2One('monitoring.check.type', 'Type', required=True)
    scheduler = fields.Many2One('monitoring.scheduler', 'Scheduler',
        required=True)
    active = fields.Boolean('Active')
    checks = fields.One2Many('monitoring.check', 'plan', 'Checks')

    @classmethod
    def __setup__(cls):
        super(CheckPlan, cls).__setup__()
        cls._buttons.update({
                'check': {},
                })

    @staticmethod
    def default_active():
        return True

    @classmethod
    @ModelView.button
    @ModelView.button
    def check(cls, plans):
        Check = Pool().get('monitoring.check')
        ResultType = Pool().get('monitoring.result.type')
        to_create = []
        for plan in plans:
            integer_to_create = []
            float_to_create = []
            char_to_create = []
            res = plan.type.check(plan)
            for result in res:
                t = ResultType.search([
                        ('internal_name', '=', result['result']),
                        ], limit=1)
                if not t:
                    sys.stderr.write('Could not store result "%s".\n'
                        % result['result'])
                    continue
                t = t[0]
                if t.type == 'integer':
                    integer_to_create.append({
                            'type': t.id,
                            'value': result['integer_value'],
                            'uom': result.get('uom', t.uom.id),
                            })
                elif t.type == 'float':
                    float_to_create.append({
                            'type': t.id,
                            'value': result['float_value'],
                            'uom': result.get('uom', t.uom.id),
                            })
                elif t.type == 'char':
                    char_to_create.append({
                            'type': t.id,
                            'value': result['char_value'],
                            })
                else:
                    sys.stderr.write('Unknown type "%s" for result "%s".\n'
                        % (t.type, result['result']))
                    continue


            to_create.append({
                    'timestamp': datetime.now(),
                    'plan': plan.id,
                    'type': plan.type.id,
                    'item': plan.item.id,
                    'integer_results': [('create', integer_to_create)],
                    'float_results': [('create', float_to_create)],
                    'char_results': [('create', char_to_create)],
                    })
        if to_create:
            Check.create(to_create)


class Check(ModelSQL, ModelView):
    'Monitoring Check'
    __name__ = 'monitoring.check'
    timestamp = fields.DateTime('Timestamp', required=True)
    plan = fields.Many2One('monitoring.check.plan', 'Plan', required=True)
    type = fields.Many2One('monitoring.check.type', 'Type', required=True)
    item = fields.Many2One('network.item', 'Item', required=True)
    integer_results = fields.One2Many('monitoring.result.integer', 'check',
        'Integer Results')
    float_results = fields.One2Many('monitoring.result.float', 'check',
        'Float Results')
    char_results = fields.One2Many('monitoring.result.char', 'check',
        'Char Results')

    @classmethod
    def __setup__(cls):
        super(Check, cls).__setup__()
        cls._order.insert(0, ('timestamp', 'DESC'))


class ResultInteger(ModelSQL, ModelView):
    'Monitoring Result Integer'
    __name__ = 'monitoring.result.integer'
    check = fields.Many2One('monitoring.check', 'Check', required=True)
    type = fields.Many2One('monitoring.result.type', 'Type', required=True)
    value = fields.Integer('Value')
    uom = fields.Many2One('product.uom', 'UoM', required=True)


class ResultFloat(ModelSQL, ModelView):
    'Monitoring Result Float'
    __name__ = 'monitoring.result.float'
    check = fields.Many2One('monitoring.check', 'Check', required=True)
    type = fields.Many2One('monitoring.result.type', 'Type', required=True)
    value = fields.Float('Value')
    uom = fields.Many2One('product.uom', 'UoM', required=True)


class ResultChar(ModelSQL, ModelView):
    'Monitoring Result Char'
    __name__ = 'monitoring.result.char'
    check = fields.Many2One('monitoring.check', 'Check', required=True)
    type = fields.Many2One('monitoring.result.type', 'Type', required=True)
    value = fields.Char('Value')


class Alert(ModelSQL, ModelView):
    'Monitoring Alert'
    __name__ = 'monitoring.alert'
    items = fields.Many2Many('monitoring.alert-network.item', 'alert', 'item',
        'Items')
    result_type = fields.Many2One('monitoring.result.type', 'Result Type')
    expression = fields.Text('Expression')
    # Take into account UOM conversion


class AlertItem(ModelSQL):
    'Monitoring Alert - Network Item'
    __name__ = 'monitoring.alert-network.item'
    item = fields.Many2One('network.item', 'Item', required=True)
    alert = fields.Many2One('monitoring.alert', 'Alert', required=True)


class Item:
    __name__ = 'network.item'
    plans = fields.One2Many('monitoring.check.plan', 'item', 'Check Plans')
    checks = fields.One2Many('monitoring.check', 'item', 'Checks')
    alerts = fields.Many2Many('monitoring.alert-network.item', 'item', 'alert',
        'Alerts')

# Zabbix structure:
# A template contains:
#
# - Applications
# - Items
# - Triggers
# - Graphs
# - Screens
# - Discovery rules
# - Web scenarios
#
# An application has a m2m relationship with items. Example Applications include CPU, FileSystems, Performance. It is just a classification of the items
# which are the checks to be done.
#
# Triggers are boolean expressions on top of the values of the items. (Each item has an internal value which can be used by the trigger). The result of a
#
# A Trigger can be classified in only one of the following states:
#
# - Not classified
# - Information
# - Warning
# - Average
# - High
# - Disaster
#
# Examples of Graphs include:
#
# - CPU load: which shows load for 1 min, 5 min and 15 min average in a single chart. That is, a graph indicates which "Item" results should be used and how are processed (for example, use the average, drawing style, color, etc).
#
# Screens are dashboards.
#
# Discovery rules allow finding new stuff such as new filesystems or network interfaces. Discovery rules have several subitems linked: "Item Prototypes", "Trigger Prototypes", "Graph prototypes" and "Host prototypes".
#
# "Item prototypes" are Item definitions that will be created dynamically with all discovered stuff. For example, "Free disk space on %s" where %s would be the discovered item.
#
# One interesting thing is that it is possible to see all triggers using a given Item.
