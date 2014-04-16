#include "communication.h"





void set_up_comm() {
	printf("[ setup communication ] \n");
	DM_num = 0;
	dms = (domain_manager* ) malloc(sizeof(domain_manager)* 3);
	user_num = 0;
	users = (user* ) malloc(sizeof(user)* 2);
	char param[1024];
	size_t count = fread(param, 1, 1024, stdin);
	if (!count) pbc_die("input error");
	pairing_init_set_buf(pairing, param, count);
}

void set_up_domain_manager(domain_manager* who, public_key parent) {
	printf("[ SETUP_DM ");
	if (parent.level == 0) {
		printf(" if %s ]\n", who->name);
		public_key temp = init_public_key(&parent);
		who->pk.ID_tuple = temp.ID_tuple;
		who->pk.level = temp.level;
		who -> MK =  create_DM(ROOT.MK, who->pk, *(ROOT.param));
		
		param_copy_PP(&(who->param), ROOT.param);
		
			}
	else{
		printf(" else  %s ]\n", who->name);
		domain_manager x;
		domain_manager* y = dm_from_publickey(parent);
		public_key temp1 = init_public_key(&parent);
		who->pk.ID_tuple = temp1.ID_tuple;
		who->pk.level = temp1.level;
		x.MK = create_DM(y->MK, who->pk, *(ROOT.param) );
		who->MK = x.MK;
		param_copy_PP(&(who->param),ROOT.param);
		
		//updateparentchildren
		
		public_key* temp = (public_key* ) malloc(sizeof(public_key) * (y->number_of_children + 1) );
		int i;
		for (i = 0; i < y->number_of_children; ++i) {
			public_key_copy(temp + i, y->children_dm  + i);
		}
		y->children_dm += 1;
		public_key_copy(temp + i, &(who->pk));

		
		for(i = 0; i < y->number_of_children  - 1; ++i) {
			free_public_key(y->children_dm  + i);
		}
		
	  y->children_dm = temp;
		
		}
}

void set_up_user(user* user, public_key parent_pk)  {
	domain_manager* parent_dm = dm_from_publickey(parent_pk);
	public_key pk_u = init_public_key(&parent_dm);
	user->pk = pk_u;
	create_user_returntype rt = create_user(parent_dm->MK, pk_u, 
}

int get_next_id(public_key* parent) {
	if(parent->level == 0) {
		return ROOT.number_of_dm++;
	}
	domain_manager* par = dm_from_publickey(*parent);
	int ret = par->id;
	par->id += 1;
	return ret;
}

domain_manager* dm_from_publickey(public_key pk) {
	int i;
	for(i = 0; i < DM_num; ++i) {
		if( pkcomp(pk, dms[i].pk)) {
			return dms + i;
		}
	}
	return NULL;
}

int pkcomp(public_key a, public_key b) {
	int i;
	if(a.level != b.level) {
		return 0;
	}
	for(i = 0; i <= a.level; ++i) {
		if(a.ID_tuple[i] != b.ID_tuple[i]) {
			return 0;
		}
	}
	return 1;
}

void get_params(params* dest) {
	param_copy(dest, ROOT->param);
}

user_secret_key add_attribute(public_key pk, attribute* att) {
	user_secret_key ret;
	//trick it s just a fake public_key
	public_key par_pk;
	par_pk.ID_tuple = att->DM.ID_tuple;
	par_pk.level = att->DM.level - 1;
	domain_manager* par = dm_from_publickey(&par_pk);
	Q_tuple SK_u = generate_SK_u(att_pk ,pk);
	element_t SK_a;
	generate_SK_ua(&SK_a, par, pk, att);
	ret.SK_a = (element_t* ) malloc( sizeof(element_t));
	ret.number_of_attributes = 1;
	element_init_G1(ret.SK_a[0], pairing);
	element_set(ret.SK_a[0], SK_a);
	element_clear(SK_a);
	ret.Q_tuple = SK_u;
	return ret;
}
