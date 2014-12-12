# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
import sys
#import ast
import xmlrpclib
from datetime import datetime
import random
import string
import hashlib
from itertools import izip, chain
from decimal import Decimal
import logging

try:
    import bcrypt
except ImportError:
    bcrypt = None

from trytond.tools import safe_eval
from trytond.model import ModelSQL, ModelView, fields
from trytond.pool import Pool, PoolMeta
from trytond.pyson import Eval
from trytond.config import config
from trytond.rpc import RPC
from trytond.transaction import Transaction


__all__ = ['CheckType', 'ResultType', 'StateType', 'StateIndicator',
    'StateIndicatorLine', 'Scheduler', 'CheckPlan', 'StateIndicatorCheckPlan',
    'Check', 'State', 'ResultInteger', 'ResultFloat', 'ResultChar',
    'AssetPartyNotification', 'SynchroMapping', 'Asset', 'StateTypeParty',
    'Party', 'RelationType']
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
    monitoring_asset = fields.Many2One('asset', 'Monitoring Asset',
        required=True)
    # TODO: Make monitored_asset required?
    monitored_asset = fields.Many2One('asset', 'Monitored Asset')
    type = fields.Many2One('monitoring.check.type', 'Type', required=True)
    scheduler = fields.Many2One('monitoring.scheduler', 'Scheduler',
        required=True)
    active = fields.Boolean('Active')
    checks = fields.One2Many('monitoring.check', 'plan', 'Checks')
    indicators = fields.Many2Many(
        'monitoring.state.indicator-monitoring.check.plan', 'plan', 'indicator',
        'State Indicators')
    attribute_set = fields.Many2One('asset.attribute.set', 'Set')
    attributes = fields.Dict('asset.attribute', 'Attributes',
        domain=[
            ('sets', '=', Eval('attribute_set', -1)),
            ],
        depends=['attribute_set'],
        states={
            'readonly': ~Eval('attribute_set', {}),
            })

    @classmethod
    def __setup__(cls):
        super(CheckPlan, cls).__setup__()
        cls._buttons.update({
                'check': {},
                })

    @staticmethod
    def default_active():
        return True

    @staticmethod
    def get_indicators(plan, type_, value):
        states_to_create = []
        for indicator in plan.indicators:
            if indicator.result_type != type_:
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
                    'state': state_type.id,
                    'value': unicode(value),
                    })
        return states_to_create

    @classmethod
    def create_indicators(cls, checks):
        State = Pool().get('monitoring.state')
        to_create = []
        for check in checks:
            for result in chain(check.integer_results, check.float_results,
                    check.char_results):
                vals = cls.get_indicators(check.plan, result.type,
                    result.value)
                for state in vals:
                    state['check'] = check.id
                to_create += vals
        State.create(to_create)

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

                states_to_create = cls.get_indicators(plan, t, value)

            to_create.append({
                    'timestamp': datetime.now(),
                    'plan': plan.id,
                    'type': plan.type.id,
                    'monitoring_asset': plan.monitoring_asset.id,
                    'monitored_asset': (plan.monitored_asset.id
                        if plan.monitored_asset else None),
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

    def get_attribute(self, name):
        """
        Returns the value of the given attribute. If attribute is not set in
        the plan, it will be searched in the monitored asset.
        """
        if self.attributes and name in self.attributes:
            return self.attributes[name]
        value = None
        if self.monitored_asset:
            value = self.monitored_asset.get_attribute(name)
        if value is None:
            value = self.monitoring_asset.get_attribute(name)
        return value


class StateIndicatorCheckPlan(ModelSQL, ModelView):
    'Monitoring State Indicator - Monitoring Check Plan'
    __name__ = 'monitoring.state.indicator-monitoring.check.plan'
    indicator = fields.Many2One('monitoring.state.indicator', 'Indicator',
        required=True)
    plan = fields.Many2One('monitoring.check.plan', 'Plan', required=True)
    last_check = fields.Function(fields.Many2One('monitoring.check',
            'Last Check'), 'get_last_check')
    last_state = fields.Function(fields.Many2One('monitoring.state', 'State'),
        'get_last_state')
    last_state_type = fields.Function(fields.Many2One('monitoring.state.type',
            'State Type'), 'get_last_state_type')
    last_state_value = fields.Function(fields.Char('Value'),
        'get_last_state_value')
    monitoring_asset = fields.Function(fields.Many2One('asset',
            'Monitoring Asset'), 'get_asset', searcher='search_asset')
    monitored_asset = fields.Function(fields.Many2One('asset',
            'Monitored Asset'), 'get_asset', searcher='search_asset')
    color = fields.Function(fields.Char('Color'), 'get_color')

    def get_last_check(self, name):
        if not self.plan.checks:
            return None
        return self.plan.checks[0].id

    def get_last_state(self, name):
        check = self.last_check
        if not check:
            return
        for state in check.states:
            if state.indicator == self.indicator:
                return state.id

    def get_last_state_type(self, name):
        state = self.last_state
        if not state:
            return
        return state.state.id

    def get_last_state_value(self, name):
        state = self.last_state
        if not state:
            return
        return self.last_state.value

    def get_color(self, name):
        state = self.last_state_type
        if not state:
            return
        return state.color

    def get_asset(self, name):
        asset = getattr(self.plan, name)
        if asset:
            return asset.id

    @classmethod
    def search_asset(cls, name, clause):
        return [('plan.%s' % name,) + tuple(clause[1:])]


class Check(ModelSQL, ModelView):
    'Monitoring Check'
    __name__ = 'monitoring.check'
    _rec_name = 'timestamp'
    timestamp = fields.DateTime('Timestamp', required=True)
    plan = fields.Many2One('monitoring.check.plan', 'Plan', required=True)
    type = fields.Many2One('monitoring.check.type', 'Type', required=True)
    monitoring_asset = fields.Many2One('asset', 'Monitoring Asset',
        required=True)
    monitored_asset = fields.Many2One('asset', 'Monitored Asset')
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
    _rec_name = 'check'
    check = fields.Many2One('monitoring.check', 'Check', required=True,
        ondelete='CASCADE')
    indicator = fields.Many2One('monitoring.state.indicator', 'Indicator',
        required=True)
    monitoring_asset = fields.Function(fields.Many2One('asset',
            'Monitoring Asset'), 'get_asset', searcher='search_asset')
    monitored_asset = fields.Function(fields.Many2One('asset',
            'Monitored Asset'), 'get_asset', searcher='search_asset')
    state = fields.Many2One('monitoring.state.type', 'State', required=True)
    color = fields.Function(fields.Char('Color'), 'get_color')
    value = fields.Char('Value')

    @classmethod
    def __setup__(cls):
        super(State, cls).__setup__()
        cls._order.insert(0, ('check', 'DESC'))

    def get_asset(self, name):
        return getattr(self.check, name)

    @classmethod
    def search_asset(cls, name, clause):
        return [('check.%s' % name,) + tuple(clause[1:])]

    def get_color(self, name):
        return self.state.color if self.state else 'black'


class ResultInteger(ModelSQL, ModelView):
    'Monitoring Result Integer'
    __name__ = 'monitoring.result.integer'
    check = fields.Many2One('monitoring.check', 'Check', required=True,
        ondelete='CASCADE')
    type = fields.Many2One('monitoring.result.type', 'Type', required=True)
    value = fields.Integer('Value')
    uom = fields.Many2One('product.uom', 'UoM', required=True)


class ResultFloat(ModelSQL, ModelView):
    'Monitoring Result Float'
    __name__ = 'monitoring.result.float'
    check = fields.Many2One('monitoring.check', 'Check', required=True,
        ondelete='CASCADE')
    type = fields.Many2One('monitoring.result.type', 'Type', required=True)
    value = fields.Float('Value')
    uom = fields.Many2One('product.uom', 'UoM', required=True)


class ResultChar(ModelSQL, ModelView):
    'Monitoring Result Char'
    __name__ = 'monitoring.result.char'
    check = fields.Many2One('monitoring.check', 'Check', required=True,
        ondelete='CASCADE')
    type = fields.Many2One('monitoring.result.type', 'Type', required=True)
    value = fields.Char('Value')


class AssetPartyNotification(ModelSQL):
    'Asset - Party Notification'
    __name__ = 'asset-party.party-notification'
    asset = fields.Many2One('asset', 'Asset', required=True)
    party = fields.Many2One('party.party', 'Party', required=True)


class SynchroMapping(ModelSQL):
    'Synchronization Mapping'
    __name__ = 'synchro.mapping'
    peer = fields.Char('Peer', required=True)
    local_id = fields.Integer('Local ID', required=True)
    remote_id = fields.Integer('Remote ID', required=True)
    model = fields.Char('Model Name', required=True)

    @classmethod
    def __setup__(cls):
        super(SynchroMapping, cls).__setup__()
        cls._sql_constraints += [
            ('remote_id_model_uniq', 'UNIQUE(remote_id, model)',
                'remote_id and model must be unique.')
            ]

    @staticmethod
    def default_peer():
        return 'master'


class Asset:
    __name__ = 'asset'
    plans = fields.One2Many('monitoring.check.plan', 'monitoring_asset',
        'Check Plans')
    checks = fields.One2Many('monitoring.check', 'monitoring_asset', 'Checks')
    states = fields.Function(fields.One2Many(
            'monitoring.state.indicator-monitoring.check.plan', None, 'States'),
        'get_states')
    notification_parties = fields.Many2Many('asset-party.party-notification',
        'asset', 'party', 'Notification Parties')
    login = fields.Char('Login')
    password_hash = fields.Char('Password Hash')
    password = fields.Function(fields.Char('Password'), getter='get_password',
        setter='set_password')

    @classmethod
    def __setup__(cls):
        super(Asset, cls).__setup__()
        cls.__rpc__.update({
                'update_remote_checks': RPC(readonly=False),
                'fetch_remote_assets': RPC(),
                })

    def get_attribute(self, name, browsed=None):
        """
        Returns the value of the given attribute.

        Other modules may want to implement their own way of searching for a
        given attribute, for example by considering related items.
        """
        if self.attributes and name in self.attributes:
            return self.attributes[name]
        if browsed is None:
            browsed = set()
        browsed.add(self)
        for relation in self.relations:
            if relation.to in browsed:
                continue
            if relation.type.search_attributes:
                value = relation.to.get_attribute(name)
                if value is not None:
                    return value
        return None

    def get_states(self, name):
        IndicatorPlan = Pool().get(
            'monitoring.state.indicator-monitoring.check.plan')
        records = IndicatorPlan.search([('monitoring_asset', '=', self.id)])
        return [x.id for x in records]

    def get_password(self, name):
        return 'x' * 10

    @classmethod
    def set_password(cls, users, name, value):
        if value == 'x' * 10:
            return
        to_write = []
        for user in users:
            to_write.extend([[user], {
                        'password_hash': cls.hash_password(value),
                        }])
        cls.write(*to_write)

    @classmethod
    def _get_login(cls, login):
        cursor = Transaction().cursor
        table = cls.__table__()
        cursor.execute(*table.select(table.id, table.password_hash,
                where=(table.login == login) & table.active))
        result = cursor.fetchone() or (None, None)
        return result

    @classmethod
    def get_login(cls, login, password):
        '''
        Return user id if password matches
        '''
        user_id, password_hash = cls._get_login(login)
        if user_id:
            if cls.check_password(password, password_hash):
                return user_id
        return 0

    @staticmethod
    def hash_method():
        return 'bcrypt' if bcrypt else 'sha1'

    @classmethod
    def hash_password(cls, password):
        '''Hash given password in the form
        <hash_method>$<password>$<salt>...'''
        if not password:
            return ''
        return getattr(cls, 'hash_' + cls.hash_method())(password)

    @classmethod
    def check_password(cls, password, hash_):
        if not hash_:
            return False
        hash_method = hash_.split('$', 1)[0]
        return getattr(cls, 'check_' + hash_method)(password, hash_)

    @classmethod
    def hash_sha1(cls, password):
        if isinstance(password, unicode):
            password = password.encode('utf-8')
        salt = ''.join(random.sample(string.ascii_letters + string.digits, 8))
        hash_ = hashlib.sha1(password + salt).hexdigest()
        return '$'.join(['sha1', hash_, salt])

    @classmethod
    def check_sha1(cls, password, hash_):
        if isinstance(password, unicode):
            password = password.encode('utf-8')
        if isinstance(hash_, unicode):
            hash_ = hash_.encode('utf-8')
        hash_method, hash_, salt = hash_.split('$', 2)
        salt = salt or ''
        assert hash_method == 'sha1'
        return hash_ == hashlib.sha1(password + salt).hexdigest()

    @classmethod
    def hash_bcrypt(cls, password):
        if isinstance(password, unicode):
            password = password.encode('utf-8')
        hash_ = bcrypt.hashpw(password, bcrypt.gensalt())
        return '$'.join(['bcrypt', hash_])

    @classmethod
    def check_bcrypt(cls, password, hash_):
        if isinstance(password, unicode):
            password = password.encode('utf-8')
        if isinstance(hash_, unicode):
            hash_ = hash_.encode('utf-8')
        hash_method, hash_ = hash_.split('$', 1)
        assert hash_method == 'bcrypt'
        return hash_ == bcrypt.hashpw(password, hash_)

    @staticmethod
    def object_to_dict(obj, peer='master', mappings=None, model_data=False):
        ModelData = Pool().get('ir.model.data')
        if mappings is None:
            mappings = {}
        res = {}
        res['id'] = obj.id
        if model_data:
            records = ModelData.search([
                    ('db_id', '=', obj.id),
                    ('model', '=', obj.__name__),
                    ])
            value = None
            if records:
                value = (records[0].module, records[0].fs_id)
            res['__model_data__'] = value
        for name, field in obj._fields.iteritems():
            value = getattr(obj, name)
            if isinstance(field, (fields.Function, fields.One2Many,
                        fields.Many2Many)):
                continue
            if isinstance(field, fields.Many2One) and value:
                value = value.id
            elif isinstance(field, fields.Reference) and value:
                # TODO: Reference fields
                value = ''
            if name in mappings and value:
                remote, = SynchroMapping.search([
                        ('local_id', '=', value),
                        ('model', '=', mappings[name]),
                        ('peer', '=', peer),
                        ])
                value = remote.remote_id
            res[name] = value
        return res

    @staticmethod
    def export_objects(objects, peer='master', mappings=None, model_data=False):
        res = []
        for obj in objects:
            res.append(Asset.object_to_dict(obj, peer=peer, mappings=mappings,
                    model_data=model_data))
        return res

    @staticmethod
    def dict_to_object(record, cls, peer='master', overrides=None,
            mappings=None):
        SynchroMapping = Pool().get('synchro.mapping')
        if overrides is None:
            overrides = {}
        if mappings is None:
            mappings = {}
        #obj = {}
        obj = cls()
        for name, value in record.iteritems():
            if name == '__model_data__':
                continue
            value = overrides.get(name, value)
            if name in mappings and value:
                local, = SynchroMapping.search([
                        ('remote_id', '=', value),
                        ('model', '=', mappings[name]),
                        ('peer', '=', peer),
                        ])
                value = local.local_id
            #obj[name] = value
            setattr(obj, name, value)
        return obj

    @staticmethod
    def import_objects(records, cls, peer='master', overrides=None,
            mappings=None):
        SynchroMapping = Pool().get('synchro.mapping')
        ModelData = Pool().get('ir.model.data')

        to_create = []
        new_records = []
        map_records = []
        for record in records:
            if '__model_data__' in record:
                value = record['__model_data__']
                map_records.append({
                        'local_id': ModelData.get_id(value[0], value[1]),
                        'remote_id': record['id'],
                        'model': cls.__name__,
                        'peer': peer,
                        })
                continue
            if record.get('id') and SynchroMapping.search([
                        ('remote_id', '=', record['id']),
                        ('peer', '=', peer),
                        ]):
                continue
            to_create.append(Asset.dict_to_object(record, cls, peer=peer,
                    overrides=overrides, mappings=mappings))
            new_records.append(record)
        local_objects = cls.create([x._save_values for x in to_create])
        for local, remote in izip(local_objects, new_records):
            map_records.append({
                    'local_id': local.id,
                    'remote_id': remote['id'],
                    'model': cls.__name__,
                    'peer': peer,
                    })
        SynchroMapping.create(map_records)
        return local_objects

    @classmethod
    def fetch_remote_assets(cls, login, password):
        AssetRelationAll = Pool().get('asset.relation.all')
        ResultType = Pool().get('monitoring.result.type')

        asset_id = cls.get_login(login, password)
        if not asset_id:
            logging.getLogger('monitoring').error('No asset found for login %s' %
                login)
            return
        asset = cls(asset_id)

        products = []

        assets = []
        assets.append(asset)
        plans = []
        schedulers = set()
        check_types = set()
        attribute_sets = set()
        if asset.attribute_set:
            attribute_sets.add(asset.attribute_set)
        for plan in asset.plans:
            if plan.monitored_asset:
                assets.append(plan.monitored_asset)
                if plan.monitored_asset.attribute_set:
                    attribute_sets.add(plan.monitored_asset.attribute_set)
            plans.append(plan)
            schedulers.add(plan.scheduler)
            check_types.add(plan.type)

        result_types = ResultType.search([])

        data = {}
        data['schedulers'] = cls.export_objects(list(schedulers))
        data['check_types'] = cls.export_objects(list(check_types),
            model_data=True)
        data['result_types'] = cls.export_objects(result_types, model_data=True)
        data['plans'] = cls.export_objects(plans)
        data['asset_attribute_sets'] = cls.export_objects(list(attribute_sets))
        data['assets'] = cls.export_objects(assets)
        return data

    @classmethod
    def update_remote_checks(cls, login, password, data):
        if not cls.get_login(login, password):
            return

        pool = Pool()
        Check = pool.get('monitoring.check')
        IntegerResult = pool.get('monitoring.result.integer')
        FloatResult = pool.get('monitoring.result.float')
        CharResult = pool.get('monitoring.result.char')
        CheckPlan = pool.get('monitoring.check.plan')

        if not data['checks']:
            return
        checks = cls.import_objects(data['checks'], Check, peer=login)
        cls.import_objects(data['integer_results'], IntegerResult, peer=login,
            mappings={
                'check': 'monitoring.check',
                })
        cls.import_objects(data['float_results'], FloatResult, peer=login,
            mappings={
                'check': 'monitoring.check',
                })
        cls.import_objects(data['char_results'], CharResult, peer=login,
            mappings={
                'check': 'monitoring.check',
                })
        CheckPlan.create_indicators(Check.browse([x.id for x in checks]))

    @classmethod
    def sync(cls):
        pool = Pool()
        Check = pool.get('monitoring.check')
        IntegerResult = pool.get('monitoring.result.integer')
        FloatResult = pool.get('monitoring.result.float')
        CharResult = pool.get('monitoring.result.char')
        Plan = pool.get('monitoring.check.plan')
        Scheduler = pool.get('monitoring.scheduler')
        AssetAttributeSet = pool.get('asset.attribute.set')
        Asset = pool.get('asset')
        Product = pool.get('product.product')
        Template = pool.get('product.template')
        SynchroMapping = pool.get('synchro.mapping')
        ModelData = pool.get('ir.model.data')
        CheckType = pool.get('monitoring.check.type')
        ResultType = pool.get('monitoring.result.type')

        data = {}
        checks = Check.search([])
        data['checks'] = cls.export_objects(checks, mappings={
                'plan': 'monitoring.check.plan',
                'monitoring_asset': 'asset',
                'monitored_asset': 'asset',
                })
        integers = IntegerResult.search([])
        data['integer_results'] = cls.export_objects(integers)
        floats = FloatResult.search([])
        data['float_results'] = cls.export_objects(floats)
        chars = CharResult.search([])
        data['char_results'] = cls.export_objects(chars)

        uri = config.get('monitoring', 'uri')
        username = config.get('monitoring', 'username')
        password = config.get('monitoring', 'password')
        server = xmlrpclib.ServerProxy(uri, allow_none=True)
        context = server.model.res.user.get_preferences(True, {})
        server.model.asset.update_remote_checks(username, password, data, context)
        data = server.model.asset.fetch_remote_assets(username, password, context)

        Check.delete(checks)
        IntegerResult.delete(checks)
        FloatResult.delete(checks)
        CharResult.delete(checks)

        Plan.delete(Plan.search([]))
        Scheduler.delete(Scheduler.search([]))
        Asset.delete(Asset.search([]))

        SynchroMapping.delete(SynchroMapping.search([]))

        # TODO: Maybe create a product with the module and deactivate it by
        # default. The problem would be if another module adds required fields.
        asset_product = Product.search([
                ('type', '=', 'assets'),
                ('code', '=', 'monitoring'),
                ], limit=1)
        if not asset_product:
            asset_product = Template.create([{
                        'name': 'Monitoring Asset',
                        'type': 'assets',
                        'list_price': Decimal(0),
                        'cost_price': Decimal(0),
                        'default_uom': ModelData.get_id('product', 'uom_unit'),
                        'products': [('create', [{
                                        'code': 'monitoring',
                                        }])]
                        }])
            asset_product = Product.search([
                    ('type', '=', 'assets'),
                    ('code', '=', 'monitoring'),
                    ], limit=1)
        asset_product = asset_product[0]
        cls.import_objects(data['asset_attribute_sets'], AssetAttributeSet)
        cls.import_objects(data['assets'], Asset, overrides={
                'product': asset_product.id,
                })
        cls.import_objects(data['schedulers'], Scheduler)
        cls.import_objects(data['plans'], Plan, mappings={
                'monitoring_asset': 'asset',
                'monitored_asset': 'asset',
                'scheduler': 'monitoring.scheduler',
                })
        cls.import_objects(data['check_types'], CheckType)
        cls.import_objects(data['result_types'], ResultType)


class StateTypeParty(ModelSQL):
    'Monitoring State - Party'
    __name__ = 'monitoring.state.type-party.party'
    type = fields.Many2One('monitoring.state.type', 'Type', required=True)
    party = fields.Many2One('party.party', 'Party', required=True)


class Party:
    __name__ = 'party.party'
    # TODO: Add calculated One2Many that shows all indicators in their current
    # state. Should it include states of related assets?
    notification_assets = fields.Many2Many('asset-party.party-notification',
        'party', 'asset', 'Notification Assets')
    notification_types = fields.Many2Many('monitoring.state.type-party.party',
        'party', 'type', 'Types')


class RelationType:
    __name__ = 'asset.relation.type'
    search_attributes = fields.Boolean('Search Attributes')


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
