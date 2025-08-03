#include "capture.h"

t_list *lst_init(void *content)
{
	t_list *new;

	new->content = content;
	new->next = NULL;
	return new;
}

t_list *lst_add_front(t_list **lst, void *content)
{
	t_list *new;

	new->content = content;
	new->next = *lst;
	return new;
}

t_list *lst_add_rear(t_list **lst, void *content)
{
	t_list *new;

	new = lst_init(content);
	while ((*lst) && (*lst)->next)
		lst = &(*lst)->next;
	*lst = new;
	return *lst;
}
