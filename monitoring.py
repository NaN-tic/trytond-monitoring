# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
import sys
import xmlrpclib
from datetime import datetime
import random
import string
import hashlib
from itertools import izip, chain, groupby
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
            'required': Eval('type') == 'float',
            'invisible': Eval('type') != 'float',
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

    @classmethod
    def copy(cls, plans, default=None):
        if default is None:
            default = {}
        if 'checks' not in default:
            default['checks'] = None
        return super(CheckPlan, cls).copy(plans, default)

    @staticmethod
    def get_indicators(plan, type_, value, label, payload):
        states_to_create = []
        for indicator in plan.indicators:
            if indicator.result_type != type_:
                continue
            state_type = None
            for line in indicator.lines:
                #ast.literal_eval(indicator.expression)
                if safe_eval(line.expression, {
                            'value': value,
                            'label': label,
                            'payload': payload,
                            }):
                    state_type = line.state_type
                    break
            if not state_type:
                state_type = indicator.default_state_type
            states_to_create.append({
                    'indicator': indicator.id,
                    'state': state_type.id,
                    'value': unicode(value),
                    'label': label,
                    'payload': payload,
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
                    result.value, result.label, result.payload)
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
            logging.info('Checking %s' % plan.type.internal_name)
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
                label = result.get('label')
                payload = result.get('payload')
                if t.type == 'integer':
                    value = result['integer_value']
                    integer_to_create.append({
                            'type': t.id,
                            'value': result['integer_value'],
                            'label': label,
                            'payload': payload,
                            })
                elif t.type == 'float':
                    value = result['float_value']
                    float_to_create.append({
                            'type': t.id,
                            'value': result['float_value'],
                            'uom': result.get('uom', t.uom.id),
                            'label': label,
                            'payload': payload,
                            })
                elif t.type == 'char':
                    value = result['char_value']
                    char_to_create.append({
                            'type': t.id,
                            'value': result['char_value'],
                            'label': label,
                            'payload': payload,
                            })
                else:
                    sys.stderr.write('Unknown type "%s" for result "%s".\n'
                        % (t.type, result['result']))
                    continue

                states_to_create = cls.get_indicators(plan, t, value, label,
                    payload)

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
        Check = Pool().get('monitoring.check')
        plans = cls.search([])
        to_check = []
        Transaction().cursor.lock(cls._table)
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

        cls.check(cls.browse([x.id for x in to_check]))
        logging.info('check_all finished')

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
            'Last Check'), 'get_lasts')
    last_state = fields.Function(fields.Many2One('monitoring.state', 'State'),
        'get_lasts')
    last_state_type = fields.Function(fields.Many2One('monitoring.state.type',
            'State Type'), 'get_lasts')
    last_state_value = fields.Function(fields.Char('Value'),
        'get_lasts')
    monitoring_asset = fields.Function(fields.Many2One('asset',
            'Monitoring Asset'), 'get_asset', searcher='search_asset')
    monitored_asset = fields.Function(fields.Many2One('asset',
            'Monitored Asset'), 'get_asset', searcher='search_asset')
    color = fields.Function(fields.Char('Color'), 'get_lasts')

    @classmethod
    def get_lasts(cls, records, names):
        res = {}
        for name in ('last_state', 'last_check', 'last_state_type',
                'last_state_value', 'color'):
            res[name] = dict([(x.id, None) for x in records])

        plan_ids = [x.plan.id for x in records]
        Check = Pool().get('monitoring.check')
        State = Pool().get('monitoring.state')
        Plan = Pool().get('monitoring.check.plan')
        check_ids = []
        mapping = {}
        plan_ids = list(set([x.plan.id for x in records]))

        checks = Check.search([
                ('plan', 'in', plan_ids),
                ], order=[('plan', 'ASC'), ('timestamp', 'DESC')])
        plan_check_map = {}
        for key, group in groupby(checks, lambda x: x.plan.id):
            for item in group:
                plan_check_map[key] = item.id
                break

        #plan_check_map= {}
        #for plan in  Plan.browse(plan_ids):
        #    if plan.checks:
        #        plan_check_map[plan.id] = plan.checks[0].id

        logging.info("Preparing mapping")
        for record in records:
            check_id = plan_check_map.get(record.plan.id)
            if check_id:
                mapping[(check_id, record.indicator.id)] = record.id
                res['last_check'][record.id] = check_id
                check_ids.append(check_id)

        states = State.search([
                ('check', 'in', check_ids),
                ])
        for state in states:
            key = (state.check.id, state.indicator.id)
            if key in mapping:
                res['last_state'][mapping[key]] = state.id
                res['last_state_type'][mapping[key]] = state.state.id
                res['last_state_value'][mapping[key]] = state.value
                res['color'][mapping[key]] = (state.state.color if state.state
                    else 'black')
        return res

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
    label = fields.Char('Label')
    payload = fields.Text('Payload')

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
    label = fields.Char('Label')
    payload = fields.Text('Payload')


class ResultFloat(ModelSQL, ModelView):
    'Monitoring Result Float'
    __name__ = 'monitoring.result.float'
    check = fields.Many2One('monitoring.check', 'Check', required=True,
        ondelete='CASCADE')
    type = fields.Many2One('monitoring.result.type', 'Type', required=True)
    value = fields.Float('Value')
    uom = fields.Many2One('product.uom', 'UoM', required=True)
    label = fields.Char('Label')
    payload = fields.Text('Payload')


class ResultChar(ModelSQL, ModelView):
    'Monitoring Result Char'
    __name__ = 'monitoring.result.char'
    check = fields.Many2One('monitoring.check', 'Check', required=True,
        ondelete='CASCADE')
    type = fields.Many2One('monitoring.result.type', 'Type', required=True)
    value = fields.Char('Value')
    label = fields.Char('Label')
    payload = fields.Text('Payload')


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
            ('remote_id_model_peer_uniq', 'UNIQUE(remote_id, model, peer)',
                'remote_id, model and peer must be unique.')
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
                'server_sync': RPC(readonly=False),
                })

    @classmethod
    def copy(cls, assets, default=None):
        if default is None:
            default = {}
        if 'checks' not in default:
            default['checks'] = None
        return super(Asset, cls).copy(assets, default)

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
        Return asset if password matches
        '''
        user_id, password_hash = cls._get_login(login)
        if user_id:
            if cls.check_password(password, password_hash):
                return cls(user_id)
        return None

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
            if isinstance(field, (fields.Function, fields.One2Many,
                        fields.Many2Many)):
                continue
            value = getattr(obj, name)
            if isinstance(field, fields.Many2One) and value:
                value = value.id
            elif isinstance(field, fields.Reference) and value:
                # TODO: Reference fields
                value = ''
            if name in mappings and value:
                db_mappings = SynchroMapping.search([
                        ('local_id', '=', value),
                        ('model', '=', mappings[name]),
                        ('peer', '=', peer),
                        ])
                assert db_mappings, ('No mappings found with local_id=%s, '
                    'model=%s, peer=%s' % (value, mappings[name], peer))
                value = db_mappings[0].remote_id
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
        obj = cls()
        for name, value in record.iteritems():
            if name == '__model_data__':
                continue
            value = overrides.get(name, value)
            if name in mappings and value:
                db_mappings = SynchroMapping.search([
                        ('remote_id', '=', value),
                        ('model', '=', mappings[name]),
                        ('peer', '=', peer),
                        ])
                assert db_mappings, ('No mappings found with remote_id=%s, '
                    'model=%s, peer=%s' % (value, mappings[name], peer))
                value = db_mappings[0].local_id
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
        local_ids = []
        for record in records:
            if record.get('id'):
                maps = SynchroMapping.search([
                        ('remote_id', '=', record['id']),
                        ('peer', '=', peer),
                        ('model', '=', cls.__name__),
                        ])
                if maps:
                    local_ids.append(maps[0].local_id)
                    continue
            if '__model_data__' in record:
                value = record['__model_data__']
                local_id = ModelData.get_id(value[0], value[1])
                map_records.append({
                        'local_id': local_id,
                        'remote_id': record['id'],
                        'model': cls.__name__,
                        'peer': peer,
                        })
                local_ids.append(local_id)
                continue
            to_create.append(Asset.dict_to_object(record, cls, peer=peer,
                    overrides=overrides, mappings=mappings))
            new_records.append(record)
        if to_create or new_records:
            new_ids = [r.id for r in cls.create([x._save_values for x in to_create])]
            for local_id, remote in izip(new_ids, new_records):
                map_records.append({
                        'local_id': local_id,
                        'remote_id': remote['id'],
                        'model': cls.__name__,
                        'peer': peer,
                        })
        else:
            new_ids = []
        if map_records:
            SynchroMapping.create(map_records)
        return cls.browse(local_ids + new_ids)

    def fetch_remote_assets(self):
        logging.info('fetch_remote_assets: %s' % self.login)
        AssetRelationAll = Pool().get('asset.relation.all')
        ResultType = Pool().get('monitoring.result.type')

        products = []

        assets = set()
        assets.add(self)
        plans = []
        schedulers = set()
        check_types = set()
        attribute_sets = set()
        if self.attribute_set:
            attribute_sets.add(self.attribute_set)
        for plan in self.plans:
            if plan.monitored_asset:
                assets.add(plan.monitored_asset)
                if plan.monitored_asset.attribute_set:
                    attribute_sets.add(plan.monitored_asset.attribute_set)
            plans.append(plan)
            schedulers.add(plan.scheduler)
            check_types.add(plan.type)

        result_types = ResultType.search([])

        data = {}
        data['schedulers'] = self.export_objects(list(schedulers))
        data['check_types'] = self.export_objects(list(check_types),
            model_data=True)
        data['result_types'] = self.export_objects(result_types,
            model_data=True)
        data['plans'] = self.export_objects(plans)
        data['asset_attribute_sets'] = self.export_objects(list(attribute_sets))
        data['assets'] = self.export_objects(list(assets))
        logging.info('fetch_remote_assets: %s finished' % self.login)
        return data

    @classmethod
    def server_sync(cls, login, password, data, clear):
        logging.info('server_sync: %s' % login)
        SynchroMapping = Pool().get('synchro.mapping')

        asset = cls.get_login(login, password)
        if not asset:
            logging.getLogger('monitoring').error('No asset found for login '
                '%s' % login)
            raise Exception('Incorrect login or password')

        if clear:
            # Should only be removed the first time a new server synchronizes.
            # Necessary in case the remote database has been cleared.
            SynchroMapping.delete(SynchroMapping.search([
                    ('peer', '=', login),
                    ]))
        else:
            asset.update_remote_checks(data)
        res = asset.fetch_remote_assets()
        logging.info('server_sync: %s finished' % login)
        return res

    def update_remote_checks(self, data):
        logging.info('update_remote_checks: %s' % self.login)
        pool = Pool()
        Check = pool.get('monitoring.check')
        IntegerResult = pool.get('monitoring.result.integer')
        FloatResult = pool.get('monitoring.result.float')
        CharResult = pool.get('monitoring.result.char')
        CheckPlan = pool.get('monitoring.check.plan')
        SynchroMapping = pool.get('synchro.mapping')
        ProductUom = pool.get('product.uom')

        if not data['checks']:
            return
        checks = self.import_objects(data['checks'], Check, peer=self.login)
        self.import_objects(data['integer_results'], IntegerResult,
            peer=self.login, mappings={
                'check': 'monitoring.check',
                })
        self.import_objects(data['product_uoms'], ProductUom, peer=self.login)
        self.import_objects(data['float_results'], FloatResult, peer=self.login,
            mappings={
                'check': 'monitoring.check',
                'uom': 'product.uom',
                })
        self.import_objects(data['char_results'], CharResult, peer=self.login,
            mappings={
                'check': 'monitoring.check',
                })
        CheckPlan.create_indicators(Check.browse([x.id for x in checks]))
        logging.info('update_remote_checks: %s finished' % self.login)

    @classmethod
    def client_sync(cls):
        logging.info('client_sync')
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
        ProductUom = pool.get('product.uom')

        Transaction().cursor.lock(Plan._table)
        data = {}

        checks = Check.search([])
        data['checks'] = cls.export_objects(checks, mappings={
                'plan': 'monitoring.check.plan',
                'monitoring_asset': 'asset',
                'monitored_asset': 'asset',
                'type': 'monitoring.check.type',
                })
        integers = IntegerResult.search([])
        data['integer_results'] = cls.export_objects(integers, mappings={
                'type': 'monitoring.result.type',
                })
        product_uoms = ProductUom.search([])
        data['product_uoms'] = cls.export_objects(product_uoms,
            model_data=True)
        floats = FloatResult.search([])
        data['float_results'] = cls.export_objects(floats, mappings={
                'type': 'monitoring.result.type',
                })
        chars = CharResult.search([])
        data['char_results'] = cls.export_objects(chars, mappings={
                'type': 'monitoring.result.type',
                })

        uri = config.get('monitoring', 'uri')
        username = config.get('monitoring', 'username')
        password = config.get('monitoring', 'password')
        server = xmlrpclib.ServerProxy(uri, allow_none=True)
        context = server.model.res.user.get_preferences(True, {})

        remote_clear = True
        if Asset.search([], limit=1):
            # Should only be removed the first time a new server synchronizes.
            # Necessary in case the remote database has been cleared.
            remote_clear = False

        data = server.model.asset.server_sync(username, password, data,
            remote_clear, context)

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
        cls.import_objects(data['check_types'], CheckType)
        cls.import_objects(data['result_types'], ResultType)
        cls.import_objects(data['plans'], Plan, mappings={
                'monitoring_asset': 'asset',
                'monitored_asset': 'asset',
                'scheduler': 'monitoring.scheduler',
                'type': 'monitoring.check.type',
                })
        logging.info('client_sync finished')


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
