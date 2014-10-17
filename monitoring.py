# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
import sys
import ast
from datetime import datetime

from trytond.tools import safe_eval
from trytond.model import ModelSQL, ModelView, fields
from trytond.pool import Pool, PoolMeta
from trytond.pyson import Eval


__all__ = ['CheckType', 'ResultType', 'StateType', 'StateIndicator',
    'StateIndicatorLine', 'Scheduler', 'CheckPlan', 'StateIndicatorCheckPlan',
    'Check', 'State', 'ResultInteger', 'ResultFloat', 'ResultChar',
    'AssetPartyNotification', 'Asset', 'StateTypeParty', 'Party']
__metaclass__ = PoolMeta


class CheckType(ModelSQL, ModelView):
    'Monitoring Check Type'
    __name__ = 'monitoring.check.type'
    name = fields.Char('Name', translate=True)
    internal_name = fields.Char('Internal Name', readonly=False)


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


class StateType(ModelSQL, ModelView):
    'Monitoring State Value'
    __name__ = 'monitoring.state.type'
    name = fields.Char('Name', translate=True, required=True)
    color = fields.Char('Color')


class StateIndicator(ModelSQL, ModelView):
    'Monitoring State Indicator'
    __name__ = 'monitoring.state.indicator'
    name = fields.Char('Name', translate=True, required=True)
    result_type = fields.Many2One('monitoring.result.type', 'Result Type',
        required=True)
    default_state_type = fields.Many2One('monitoring.state.type',
        'Default Type', required=True)
    # At least one line should be required
    lines = fields.One2Many('monitoring.state.indicator.line', 'indicator',
        'Lines', required=True)


class StateIndicatorLine(ModelSQL, ModelView):
    'Monitoring State Indicator Line'
    __name__ = 'monitoring.state.indicator.line'
    indicator = fields.Many2One('monitoring.state.indicator', 'Indicator',
        required=True)
    sequence = fields.Integer('Sequence')
    expression = fields.Text('Expression', required=True)
    state_type = fields.Many2One('monitoring.state.type', 'Type', required=True)

    @classmethod
    def __setup__(cls):
        super(StateIndicatorLine, cls).__setup__()
        cls._order.insert(0, ('indicator', 'ASC'))
        cls._order.insert(0, ('sequence', 'ASC'))

    @staticmethod
    def order_sequence(tables):
        table, _ = tables[None]
        return [table.sequence == None, table.sequence]


class Scheduler(ModelSQL, ModelView):
    'Monitoring Scheduler'
    __name__ = 'monitoring.scheduler'
    # It might make sense to create a parent and inherit values from the
    # parent similar to Nagios behaviour.
    name = fields.Char('Name', required=True, translate=True)
    normal_check_interval = fields.Float('Normal Check Interval', required=True)
    retries = fields.Integer('Retries', required=True)
    retry_check_interval = fields.Float('Retry Check Interval', required=True)


# TODO: We should probably create a scheduler queue

class CheckPlan(ModelSQL, ModelView):
    'Monitoring Check Plan'
    __name__ = 'monitoring.check.plan'
    asset = fields.Many2One('asset', 'Asset', required=True)
    type = fields.Many2One('monitoring.check.type', 'Type', required=True)
    scheduler = fields.Many2One('monitoring.scheduler', 'Scheduler',
        required=True)
    active = fields.Boolean('Active')
    checks = fields.One2Many('monitoring.check', 'plan', 'Checks')
    indicators = fields.Many2Many(
        'monitoring.state.indicator-monitoring.check.plan', 'plan', 'indicator',
        'State Indicators')

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
        pool = Pool()
        Check = pool.get('monitoring.check')
        ResultType = pool.get('monitoring.result.type')
        to_create = []
        for plan in plans:
            integer_to_create = []
            float_to_create = []
            char_to_create = []
            res = getattr(plan, plan.type.internal_name)()
            for result in res:
                t = ResultType.search([
                        ('internal_name', '=', result['result']),
                        ], limit=1)
                if not t:
                    sys.stderr.write('Could not store result type "%s". Result '
                        'was: %s\n' % (result['result'], result))
                    continue
                t = t[0]
                value = None
                if t.type == 'integer':
                    value = result['integer_value']
                    integer_to_create.append({
                            'type': t.id,
                            'value': result['integer_value'],
                            'uom': result.get('uom', t.uom.id),
                            })
                elif t.type == 'float':
                    value = result['float_value']
                    float_to_create.append({
                            'type': t.id,
                            'value': result['float_value'],
                            'uom': result.get('uom', t.uom.id),
                            })
                elif t.type == 'char':
                    value = result['char_value']
                    char_to_create.append({
                            'type': t.id,
                            'value': result['char_value'],
                            })
                else:
                    sys.stderr.write('Unknown type "%s" for result "%s".\n'
                        % (t.type, result['result']))
                    continue

                states_to_create = []
                for indicator in plan.indicators:
                    if indicator.result_type != t:
                        continue
                    state_type = None
                    for line in indicator.lines:
                        #ast.literal_eval(indicator.expression)
                        if safe_eval(line.expression, {
                                    'value': value,
                                    }):
                            state_type = line.state_type
                            break
                    if not state_type:
                        state_type = indicator.default_state_type
                    states_to_create.append({
                            'indicator': indicator.id,
                            'value': state_type.id,
                            })
                    # TODO: Should be improved to take into account previous
                    # state and notify if state is ok again

                    # Maybe standard triggers will be enough by now
                    #for party in asset.notification_parties:
                        #if state_type in party.notification_types:
                            #Template.render_and_send(configuration.email_template.id, [notification])


            to_create.append({
                    'timestamp': datetime.now(),
                    'plan': plan.id,
                    'type': plan.type.id,
                    'asset': plan.asset.id,
                    'integer_results': [('create', integer_to_create)],
                    'float_results': [('create', float_to_create)],
                    'char_results': [('create', char_to_create)],
                    'states': [('create', states_to_create)],
                    })
        if to_create:
            Check.create(to_create)

    @classmethod
    def check_all(cls):
        pool = Pool()
        Plan = pool.get('monitoring.check.plan')
        Check = pool.get('monitoring.check')
        plans = Plan.search([])
        to_check = []
        for plan in plans:
            checks = Check.search([
                    ('plan', '=', plan.id),
                    ], order=[('timestamp', 'DESC')], limit=1)
            if not checks:
                to_check.append(plan)
                continue
            last_check = checks[0]

            delta = datetime.now() - last_check.timestamp
            if (delta.seconds / 3600.0) >= plan.scheduler.normal_check_interval:
                to_check.append(plan)

        Plan.check(Plan.browse([x.id for x in to_check]))


class StateIndicatorCheckPlan(ModelSQL):
    'Monitoring State Indicator - Monitoring Check Plan'
    __name__ = 'monitoring.state.indicator-monitoring.check.plan'
    indicator = fields.Many2One('monitoring.state.indicator', 'Indicator',
        required=True)
    plan = fields.Many2One('monitoring.check.plan', 'Plan', required=True)
    state = fields.Many2One('monitoring.state', 'State')


class Check(ModelSQL, ModelView):
    'Monitoring Check'
    __name__ = 'monitoring.check'
    _rec_name = 'timestamp'
    timestamp = fields.DateTime('Timestamp', required=True)
    plan = fields.Many2One('monitoring.check.plan', 'Plan', required=True)
    type = fields.Many2One('monitoring.check.type', 'Type', required=True)
    asset = fields.Many2One('asset', 'Asset', required=True)
    integer_results = fields.One2Many('monitoring.result.integer', 'check',
        'Integer Results')
    float_results = fields.One2Many('monitoring.result.float', 'check',
        'Float Results')
    char_results = fields.One2Many('monitoring.result.char', 'check',
        'Char Results')
    states = fields.One2Many('monitoring.state', 'check', 'States')

    @classmethod
    def __setup__(cls):
        super(Check, cls).__setup__()
        cls._order.insert(0, ('timestamp', 'DESC'))


class State(ModelSQL, ModelView):
    'Monitoring State'
    __name__ = 'monitoring.state'
    check = fields.Many2One('monitoring.check', 'Check', required=True)
    indicator = fields.Many2One('monitoring.state.indicator', 'Indicator',
        required=True)
    asset = fields.Function(fields.Many2One('asset', 'Asset'), 'get_asset',
        searcher='search_asset')
    value = fields.Many2One('monitoring.state.type', 'Value', required=True)
    color = fields.Function(fields.Char('Color'), 'get_color')

    def get_asset(self, name):
        return self.check.asset.id

    @classmethod
    def search_asset(cls, name, clause):
        return [('check.asset',) + tuple(clause[1:])]

    def get_color(self, name):
        return self.value.color if self.value else 'black'


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


class AssetPartyNotification(ModelSQL):
    'Asset - Party Notification'
    __name__ = 'asset-party.party-notification'
    asset = fields.Many2One('asset', 'Asset', required=True)
    party = fields.Many2One('party.party', 'Party', required=True)


class Asset:
    __name__ = 'asset'
    plans = fields.One2Many('monitoring.check.plan', 'asset', 'Check Plans')
    checks = fields.One2Many('monitoring.check', 'asset', 'Checks')
    notification_parties = fields.Many2Many('asset-party.party-notification',
        'asset', 'party', 'Notification Parties')

    def get_attribute(self, name):
        """
        Returns the value of the given attribute.

        Other modules may want to implement their own way of searching for a
        given attribute, for example by considering related items.
        """
        return self.attributes.get(name) if self.attributes else None


class StateTypeParty(ModelSQL):
    'Monitoring State - Party'
    __name__ = 'monitoring.state.type-party.party'
    type = fields.Many2One('monitoring.state.type', 'Type', required=True)
    party = fields.Many2One('party.party', 'Party', required=True)


class Party:
    __name__ = 'party.party'
    notification_assets = fields.Many2Many('asset-party.party-notification',
        'party', 'asset', 'Notification Assets')
    notification_types = fields.Many2Many('monitoring.state.type-party.party',
        'party', 'type', 'Types')

    # TODO: Add calculated One2Many that shows all indicators in its current state.


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
