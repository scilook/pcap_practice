#include "capture.h"

t_list *lst_init(void *content)
{
	t_list *new;

	new = (t_list *)malloc(sizeof(t_list));
	new->content = content;
	new->next = NULL;
	return new;
}

t_list *lst_add_front(t_list **lst, void *content)
{
	t_list *new;

	if (!lst || !content)
		return NULL;
	if (*lst == NULL)
		return lst_init(content);
	new->content = content;
	new->next = *lst;
	return new;
}

t_list *lst_add_rear(t_list **lst, void *content)
{
	t_list *new;

	if (!lst || !content)
		return NULL;
	if (*lst == NULL)
		return lst_init(content);
	new = lst_init(content);
	while ((*lst) && (*lst)->next)
		lst = &(*lst)->next;
	*lst = new;
	return *lst;
}
