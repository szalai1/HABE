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
		who->pk = init_public_key(&parent);
		who -> MK =  create_DM(ROOT.MK, who->pk, *(ROOT.param));
		
		param_copy_PP(&(who->param), ROOT.param);
		
			}
	else{
		printf(" else  %s ]\n", who->name);
		domain_manager x;
		domain_manager* y = dm_from_publickey(parent);
		who->pk = init_public_key(&parent);
		x.MK = create_DM(y->MK, who->pk, *(ROOT.param) );
		who->MK = x.MK;
		param_copy_PP(&(who->param),ROOT.param);
		
		//updateparentchilds
		
		public_key* temp = (public_key* ) malloc(sizeof(public_key) * (y->number_of_children + 1) );
		int i;
		for (i = 0; i < y->number_of_children; ++i) {
			public_key_copy(temp + i, y->children_dm  + i);
		}
		y->children_dm += 1;
		public_key_copy(temp + i, who->pk);

		
		for(i = 0; i < y->number_of_children  - 1; ++i) {
			free_public_key(y->children_dm  + i);
		}
		
	  y->children_dm = temp;
		
		}
}

void set_up_user(user* user, public_key parent_dm)  {
	//todo
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
