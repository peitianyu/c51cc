#include "c51_gen_internal.h"
#include "../obj.h"

C51GenContext* c51_ctx_new(void)
{
	C51GenContext *ctx = calloc(1, sizeof(C51GenContext));
	if (!ctx) return NULL;

	ctx->obj = obj_new();
	if (!ctx->obj) {
		free(ctx);
		return NULL;
	}
	
	ctx->current_func = NULL;
	ctx->current_block = NULL;

	ctx->value_to_reg = NULL;
	ctx->value_to_addr = NULL;
	ctx->value_type = NULL;

	ctx->v16_regs = make_dict(NULL);
	ctx->next_v16_offset = 0;

	ctx->mmio_map = make_dict(NULL);
	ctx->label_counter = 0;

	ctx->temp_values = make_list();

	return ctx;

}

void c51_ctx_free(C51GenContext* ctx)
{
	if (!ctx) return;

	if (ctx->obj) {
		obj_free(ctx->obj);
		ctx->obj = NULL;
	}

	if (ctx->value_to_reg) { dict_clear(ctx->value_to_reg); ctx->value_to_reg = NULL; }
	if (ctx->value_to_addr) { dict_clear(ctx->value_to_addr); ctx->value_to_addr = NULL; }
	if (ctx->value_type) { dict_clear(ctx->value_type); ctx->value_type = NULL; }

	if (ctx->v16_regs) { dict_clear(ctx->v16_regs); ctx->v16_regs = NULL; }
	if (ctx->mmio_map) { dict_clear(ctx->mmio_map); ctx->mmio_map = NULL; }

	if (ctx->temp_values) { list_free(ctx->temp_values); free(ctx->temp_values); ctx->temp_values = NULL; }

	free(ctx);
    
}
